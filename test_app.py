"""Tests for the Flask web interface."""

import io

import app as web_app


def client():
    web_app.app.config.update(TESTING=True)
    return web_app.app.test_client()


def test_index_loads():
    response = client().get("/")
    assert response.status_code == 200
    assert b"Password Strength Analyzer" in response.data


def test_analyze_requires_password():
    response = client().post("/analyze", data={"password": ""})
    assert response.status_code == 400
    assert response.get_json()["error"] == "No password provided"


def test_batch_requires_nonempty_file():
    response = client().post(
        "/batch",
        data={"file": (io.BytesIO(b"\n\n"), "passwords.txt")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "File is empty"


def test_batch_response_does_not_expose_raw_password(monkeypatch):
    monkeypatch.setattr(
        web_app,
        "run_audit",
        lambda passwords: {
            "total": 1,
            "results": [{"password": passwords[0], "final_score": 2}],
            "summary": {0: 0, 1: 0, 2: 1, 3: 0, 4: 0},
            "pass_rate": 0.0,
            "pwned_count": 0,
            "generated_at": "2026-08-05T00:00:00",
        },
    )
    response = client().post(
        "/batch",
        data={"file": (io.BytesIO(b"super-secret-password\n"), "passwords.txt")},
        content_type="multipart/form-data",
    )
    result = response.get_json()["results"][0]
    assert "password" not in result
    assert result["password_masked"].startswith("su")
    assert "secret" not in response.get_data(as_text=True)
