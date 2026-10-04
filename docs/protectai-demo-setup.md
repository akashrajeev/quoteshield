# Turn on the ProtectAI local classifier for the demo

Free, no accounts, no API key. The model is ProtectAI deberta-v3-base-prompt-injection-v2 (Apache 2.0, English only), run on CPU through ONNX. The model file is about 739 MB and is never committed to the repo. Plan for about 1.5 GB of free RAM while it runs.

## One-time setup (from the repo folder, same Python env you use for the demo)

    git pull
    pip install -r requirements-classifier.txt
    python local_classifier.py --download ./models/protectai
    python local_classifier.py --check ./models/protectai

`--check` loads the model and scores one injection sentence and one plain quote. Expected: `'ok': True`, injection score near 1.0, plain quote near 0.0. It is a smoke check, not an evaluation.

## Run the demo with it on

macOS / Linux:

    export SHIELD_LOCAL_CLASSIFIER=1
    export SHIELD_LOCAL_CLASSIFIER_DIR=./models/protectai
    streamlit run streamlit_app.py

Windows PowerShell:

    $env:SHIELD_LOCAL_CLASSIFIER="1"; $env:SHIELD_LOCAL_CLASSIFIER_DIR=".\models\protectai"
    streamlit run streamlit_app.py

Set the variables in the same terminal that starts Streamlit. Your freellm proxy settings are unaffected.

## What you should see

On a run where the classifier flags a line, the verdict names it ("... and the ProtectAI local classifier") and the Security Trace evidence table shows the ProtectAI score and the flagged text. If it does not flag anything, the verdict names only what fired. Nothing is named that did not fire.

## Things to know

- If the variable is on but the model folder is missing or wrong, the run stops with an error (fail closed). It does not silently run without it.
- It can add findings only; it never removes a rule's finding.
- Whole-document scores are dev smoke results with a known caveat: at least two benign false positives at line level. Do not quote a detection rate.
- Prompt Guard 2 is not set up and is not claimed.
