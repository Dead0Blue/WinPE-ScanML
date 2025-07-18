# Détecteur de Malware PE

Une application Tkinter en Python pour analyser des fichiers PE (EXE/DLL) et détecter s’ils sont malveillants ou bénins à l’aide d’un modèle de régression logistique entraîné sur le dataset EMBER 2018.


<img width="860" height="604" alt="image" src="https://github.com/user-attachments/assets/8e0c49dd-41bd-43b6-9a8a-dd97d3865243" />

---

## 📦 Prérequis

* Python 3.8+
* Windows, macOS ou Linux
* Une console (CMD, PowerShell, Terminal…)
* 8GB+ RAM (pour l'entraînement du modèle)

---

## 🔧 Installation

1. **Cloner le dépôt**

   ```bash
   git clone https://votre-repo.git
   cd votre-repo
   ```
2. **Créer un environnement virtuel**

   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # macOS / Linux
   source venv/bin/activate
   ```
3. **Installer les dépendances**

   ```bash
   pip install -r requirements.txt
   ```
4. **Placer les fichiers du modèle**
   Assurez-vous que les fichiers suivants sont dans le même dossier que `malware_detector.py` :

   * `modele_regression_logistique.pkl`
   * `scaler.pkl`
   * `features_columns.pkl`

---

## 🧠 Entraînement du Modèle (Optionnel)

Pour ré-entraîner le modèle avec le dataset EMBER 2018 :

1. **Télécharger le dataset**
   Récupérer les données EMBER 2018 depuis EMBER GitHub :

   ```bash
   wget https://ember.elastic.co/ember_dataset_2018_2.tar.bz2
   tar -xvf ember_dataset_2018_2.tar.bz2
   ```

   ⚠️ **Note :** Le dataset EMBER initial est très volumineux. Pour éviter un biais lors de l'entraînement, nous avons réduit sa taille à 4977 lignes, en équilibrant à parts égales les échantillons malveillants (label 1) et bénins (label 0).

2. **Exécuter le script d'entraînement**

   ```bash
   python train_model.py \
     --train_data path/to/ember/train_features.jsonl \
     --test_data path/to/ember/test_features.jsonl
   ```

### Processus d'entraînement

Le script va :

* Extraire les caractéristiques PE
* Prétraiter les données
* Entraîner une régression logistique
* Évaluer les performances
* Sauvegarder le modèle (`modele_regression_logistique.pkl`)
* Sauvegarder le scaler (`scaler.pkl`)

---

## 🚀 Lancer l'application

```bash
python malware_detector.py
```

L’interface propose :

* Menu latéral pour naviguer
* Zone de dépôt ou sélection de fichier
* Barre de progression d’analyse
* Résultats détaillés avec :

  * Statut (MALICIEUX 🚨 / BENIN ✅)
  * Niveau de confiance
  * Empreintes SHA256/MD5

---

## 🛠️ Structure du projet

```text
projet/
│
├── malware_detector.py       # Script principal
├── train_model.py            # Script d'entraînement
├── modele_regression_logistique.pkl
├── scaler.pkl
├── features_columns.pkl
├── requirements.txt          # Dépendances
├── interface.png             # Capture d'écran
└── README.md
```

---

## ✨ Personnalisation

* **Thème :** Modifier les couleurs dans `malware_detector.py`
* **Modèle :** Remplacer les fichiers `.pkl` par votre propre modèle
* **Seuil de détection :** Ajuster `SEUIL_MALVEILLANT` dans le code


