# ============================================================
#  train.py  —  ESRD Prediction  —  Multi-Model Pipeline
#  Entraîne et sauvegarde 3 modèles : rf.pkl / xgb.pkl / ab.pkl
# ============================================================
import os
import pandas as pd
import numpy as np
import joblib
import warnings
warnings.filterwarnings('ignore')

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report,
    confusion_matrix, ConfusionMatrixDisplay
)
from xgboost import XGBClassifier

# ── 1. Chargement ─────────────────────────────────────────────
print("=" * 60)
print("  ESRD PREDICTION — MULTI-MODEL TRAINING PIPELINE")
print("  Models : Random Forest | XGBoost | AdaBoost")
print("=" * 60)

data = pd.read_csv("esrd_prediction_dataset.csv")
print(f"Dataset shape : {data.shape}")
print(f"ESRD Risk dist:\n{data['ESRD Risk'].value_counts()}\n")

# ── 2. Encodage catégoriel ────────────────────────────────────
CAT_COLS = [
    "Gender", "Smoking", "Alcohol", "Hypertension",
    "Coronary Artery Disease", "Cancer", "Chronic Liver Disease",
    "Diabetic Retinopathy", "NSAID", "Statin", "Metformin",
    "Insulin", "Dipeptidyl Peptidase-4 Inhibitor"
]
le = LabelEncoder()
for col in CAT_COLS:
    if col in data.columns:
        data[col] = le.fit_transform(data[col].astype(str))

data['class'] = (data['ESRD Risk'] == 'Yes').astype(int)

# ── 3. Split train / test (colonne existante) ─────────────────
data = data.reset_index(drop=True)
META_COLS    = ['Patient ID', 'Dataset Split', 'ESRD Risk', 'class']
feature_cols = [c for c in data.columns
                if c not in META_COLS
                and pd.api.types.is_numeric_dtype(data[c])]

train_idx = data.index[data['Dataset Split'] == 'Training'].tolist()
test_idx  = data.index[data['Dataset Split'] == 'Testing'].tolist()
print(f"Train: {len(train_idx)} rows  |  Test: {len(test_idx)} rows")

X_raw = data[feature_cols]
y     = data['class'].values

# ── 4. Imputation + Scaling (fit sur train seulement) ─────────
imputer = SimpleImputer(strategy='median')
X_tr    = imputer.fit_transform(X_raw.iloc[train_idx])
X_te    = imputer.transform(X_raw.iloc[test_idx])

scaler  = StandardScaler()
X_tr    = scaler.fit_transform(X_tr)
X_te    = scaler.transform(X_te)

y_train = y[train_idx]
y_test  = y[test_idx]

n_neg = int(np.sum(y_train == 0))
n_pos = int(np.sum(y_train == 1))
spw   = round(n_neg / n_pos)
print(f"Class balance — No: {n_neg}  Yes: {n_pos}  → scale_pos_weight={spw}\n")


# ── 5. Définition des modèles ─────────────────────────────────
models = {
    'rf': {
        'name': 'Random Forest',
        'filename': 'rf.pkl',
        'clf': RandomForestClassifier(
            n_estimators  = 200,
            max_depth     = 10,
            class_weight  = 'balanced',   # gère le déséquilibre
            n_jobs        = -1,
            random_state  = 42,
        ),
    },
    'xgb': {
        'name': 'XGBoost',
        'filename': 'xgb.pkl',
        'clf': XGBClassifier(
            n_estimators      = 200,
            max_depth         = 5,
            learning_rate     = 0.1,
            subsample         = 0.8,
            colsample_bytree  = 0.8,
            scale_pos_weight  = spw,
            eval_metric       = 'auc',
            n_jobs            = -1,
            random_state      = 42,
            tree_method       = 'hist',
        ),
    },
    'ab': {
        'name': 'AdaBoost',
        'filename': 'ab.pkl',
        'clf': AdaBoostClassifier(
            n_estimators  = 200,
            learning_rate = 0.5,
            random_state  = 42,
        ),
    },
}


# ── 6. Entraînement, évaluation et sauvegarde ─────────────────
def evaluate_and_save(key, cfg, X_tr, y_train, X_te, y_test):
    """Entraîne un modèle, affiche ses métriques, sauvegarde le pipeline."""
    print("=" * 60)
    print(f"  [{cfg['name']}]  Training…")
    print("=" * 60)

    clf = cfg['clf']

    # XGBoost peut utiliser eval_set
    if key == 'xgb':
        clf.fit(X_tr, y_train,
                eval_set=[(X_te, y_test)],
                verbose=False)
    else:
        clf.fit(X_tr, y_train)

    probs  = clf.predict_proba(X_te)[:, 1]
    y_pred = clf.predict(X_te)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    rec  = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1w  = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    auc  = roc_auc_score(y_test, probs)

    print(f"  Accuracy  : {acc:.4f}")
    print(f"  Precision : {prec:.4f}  (weighted)")
    print(f"  Recall    : {rec:.4f}  (weighted)")
    print(f"  F1-score  : {f1w:.4f}  (weighted)")
    print(f"  AUC-ROC   : {auc:.4f}")
    print()
    print(classification_report(y_test, y_pred,
                                 target_names=['No ESRD Risk', 'ESRD Risk'],
                                 zero_division=0))
    cm = confusion_matrix(y_test, y_pred)
    print(f"Confusion Matrix:\n{cm}\n")

    # Sauvegarde du pipeline complet
    pipeline = {
        'model':       clf,
        'imputer':     imputer,
        'scaler':      scaler,
        'features':    feature_cols,
        'cat_cols':    CAT_COLS,
        'threshold':   0.5,
        'label_names': ['No ESRD Risk', 'ESRD Risk'],
        'model_name':  cfg['name'],
        'n_features':  len(feature_cols),
        'metrics': {
            'accuracy':  acc,
            'precision': prec,
            'recall':    rec,
            'f1':        f1w,
            'auc':       auc,
        },
        'cm': cm,       # store for combined figure
        'y_pred': y_pred,
    }
    joblib.dump(pipeline, cfg['filename'])
    print(f"  ✅ Pipeline sauvegardé : {cfg['filename']}\n")
    return pipeline


saved = {}
for key, cfg in models.items():
    saved[key] = evaluate_and_save(key, cfg, X_tr, y_train, X_te, y_test)


# ── 7. Récapitulatif comparatif ───────────────────────────────
print("=" * 60)
print("  RÉCAPITULATIF COMPARATIF")
print("=" * 60)
header = f"{'Model':<18} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'AUC':>10}"
print(header)
print("-" * 60)
for key, cfg in models.items():
    m = saved[key]['metrics']
    print(
        f"{cfg['name']:<18}"
        f"{m['accuracy']:>10.4f}"
        f"{m['precision']:>10.4f}"
        f"{m['recall']:>10.4f}"
        f"{m['f1']:>10.4f}"
        f"{m['auc']:>10.4f}"
    )
print("=" * 60)
print("  Fichiers générés : rf.pkl | xgb.pkl | ab.pkl")
print("=" * 60)


# ── 8. Sauvegarde de la figure Confusion Matrix ───────────────
os.makedirs("figures", exist_ok=True)

fig, axes = plt.subplots(1, 3, figsize=(18, 5))
fig.suptitle("Confusion Matrix - Production Pipeline", fontsize=16, fontweight='bold', y=1.02)

for ax, (key, cfg) in zip(axes, models.items()):
    cm = saved[key]['cm']
    disp = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=['No ESRD Risk', 'ESRD Risk']
    )
    disp.plot(ax=ax, colorbar=False, cmap='Blues')
    ax.set_title(cfg['name'], fontsize=13, fontweight='bold', pad=10)
    ax.set_xlabel('Predicted Label', fontsize=10)
    ax.set_ylabel('True Label', fontsize=10)

plt.tight_layout()
output_path = "figures/matrices_confusion_production.png"
plt.savefig(output_path, dpi=150, bbox_inches='tight')
plt.close()
print(f"\n  ✅ Confusion matrix figure saved : {output_path}\n")


# ── 9. Fonction de prédiction réutilisable ────────────────────
def predict_esrd(patient_data: dict, model_key: str = 'xgb') -> dict:
    """
    Prédire le risque ESRD pour un nouveau patient.

    Parameters
    ----------
    patient_data : dict   — valeurs brutes des features
    model_key    : str    — 'rf' | 'xgb' | 'ab'

    Returns
    -------
    dict avec 'prediction', 'probability', 'risk_label', 'risk_pct'
    """
    filename_map = {'rf': 'rf.pkl', 'xgb': 'xgb.pkl', 'ab': 'ab.pkl'}
    pipeline = joblib.load(filename_map[model_key])

    df = pd.DataFrame([patient_data])

    le_pred = LabelEncoder()
    for col in pipeline['cat_cols']:
        if col in df.columns:
            df[col] = le_pred.fit_transform(df[col].astype(str))

    for col in pipeline['features']:
        if col not in df.columns:
            df[col] = np.nan

    X = df[pipeline['features']]
    X = pipeline['imputer'].transform(X)
    X = pipeline['scaler'].transform(X)

    prob  = pipeline['model'].predict_proba(X)[0, 1]
    pred  = int(prob >= pipeline['threshold'])
    label = pipeline['label_names'][pred]

    return {
        'model':       pipeline['model_name'],
        'prediction':  pred,
        'probability': round(float(prob), 4),
        'risk_label':  label,
        'risk_pct':    f"{prob * 100:.1f}%",
    }


# ── Exemple d'utilisation ─────────────────────────────────────
if __name__ == '__main__':
    example = {
        'Age': 65,
        'Gender': 'Male',
        'Smoking': 'Yes',
        'Alcohol': 'No',
        'Hypertension': 'Yes',
        'Coronary Artery Disease': 'No',
        'Cancer': 'No',
        'Chronic Liver Disease': 'No',
        'Diabetic Retinopathy': 'Yes',
        'Baseline Serum Creatinine (mg/dL)': 2.1,
        'Mean Serum Creatinine (mg/dL)': 1.9,
        'Cholesterol (mg/dL)': 210,
        'Triglyceride (mg/dL)': 150,
        'LDL-C (mg/dL)': 130,
        'HDL-C (mg/dL)': 45,
        'Uric Acid (mg/dL)': 7.2,
        'Calcium (mg/dL)': 9.1,
        'Phosphate (mg/dL)': 3.8,
        'Hemoglobin (g/dL)': 11.5,
        'Albumin (g/dL)': 3.9,
        'HS-CRP (mg/dL)': 0.8,
        'HbA1c (%)': 7.2,
        'Glucose (mg/dL)': 140,
        'NSAID': 'No',
        'Statin': 'Yes',
        'Metformin': 'Yes',
        'Insulin': 'No',
        'Dipeptidyl Peptidase-4 Inhibitor': 'No',
    }

    print("\n📋 Exemple de prédiction (3 modèles) :")
    for key in ['rf', 'xgb', 'ab']:
        r = predict_esrd(example, model_key=key)
        print(f"  [{r['model']:<16}]  {r['risk_label']}  ({r['risk_pct']})")
# ============================================================
#  train.py  —  ESRD Prediction  —  Multi-Model Pipeline
#  Entraîne et sauvegarde 3 modèles : rf.pkl / xgb.pkl / ab.pkl
# ============================================================
