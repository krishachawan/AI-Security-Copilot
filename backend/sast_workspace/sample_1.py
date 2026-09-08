def test_autolog_log_models_configuration(log_models):
    mlflow.paddle.autolog(log_models=log_models)

    with mlflow.start_run() as run:
        train_model()

    artifacts = MlflowClient().list_artifacts(run.info.run_id)
    assert any(x.path == "model" for x in artifacts) == log_models