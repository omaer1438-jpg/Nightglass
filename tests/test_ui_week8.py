"""UI: evidence tab, report export screen, named delete confirmation."""

from __future__ import annotations

import pytest

from app.dialogs import DeleteCaseDialog, EvidenceLinkDialog
from app.main_window import MainWindow
from app.state import AppState
from core.db import Database
from core.cases import LookupMode, NewCase
from core.findings import Finding


@pytest.fixture
def ui(qtbot, themed_app, db_path, new_case):
    db = Database(db_path)
    state = AppState(db)
    window = MainWindow(state, str(db_path.parent))
    qtbot.addWidget(window)
    window.resize(1400, 900)
    window.show()
    case = state.cases.create_case(new_case())
    state.findings.add(case.id, [Finding(module="UserRecon", title="GitHub profile", source="Sherlock",
                                         url="https://github.com/example_user", notes="owner@example.com")])
    state.open_case(case.id)
    yield window, state, case
    window.close()
    db.close()


def test_add_and_verify_evidence(qtbot, ui, monkeypatch, tmp_path):
    window, state, case = ui
    sample = tmp_path / "profile_01.png"
    sample.write_bytes(b"fake screenshot")
    monkeypatch.setattr("app.screens.case_workspace.QFileDialog.getOpenFileName",
                        lambda *a, **k: (str(sample), ""))
    finding = state.findings.list(case.id)[0]

    def link_to_finding(dialog):
        assert dialog.finding_box.count() == 2  # "None" + the case's one finding
        dialog.finding_box.setCurrentIndex(dialog.finding_box.findData(finding.id))
        return 1

    monkeypatch.setattr(EvidenceLinkDialog, "exec", link_to_finding)
    workspace = window.screens["case"]
    workspace.add_evidence.click()
    # Hashing and copying run on a worker: the button is busy, and close/delete are refused meanwhile.
    assert not workspace.add_evidence.isEnabled() and workspace.add_evidence.text() == "Adding…"
    workspace.close_btn.click()
    assert state.cases.get_case(case.id).is_open
    qtbot.waitUntil(lambda: workspace.evidence_table.rowCount() == 1, timeout=5000)
    assert workspace.add_evidence.isEnabled() and workspace.add_evidence.text() == "Add evidence"
    assert workspace.tabs.current() == "evidence"
    assert workspace.stat_evidence.value.text() == "1"
    assert workspace.evidence_table.item(0, 1).text() == "GitHub profile"
    record = state.evidence.list(case.id)[0]
    assert record.finding_id == finding.id
    assert record.description == "Added from profile_01.png"  # never the full local path
    workspace.verify_evidence()
    assert not workspace.verify_btn.isEnabled()
    qtbot.waitUntil(lambda: workspace.evidence_table.item(0, 4).text() == "Matches", timeout=5000)
    assert workspace.verify_btn.isEnabled()


def test_evidence_without_findings_skips_link_dialog(qtbot, ui, monkeypatch, tmp_path):
    window, state, _ = ui
    other = state.cases.create_case(NewCase(
        name="Own domain audit", purpose="Audit example.com", authorized_scope="example.com",
        allowed_modes=(LookupMode.LOCAL,)))
    state.open_case(other.id)
    sample = tmp_path / "notes.txt"
    sample.write_bytes(b"fake notes")
    monkeypatch.setattr("app.screens.case_workspace.QFileDialog.getOpenFileName",
                        lambda *a, **k: (str(sample), ""))
    monkeypatch.setattr(EvidenceLinkDialog, "exec", lambda self: pytest.fail("no findings, nothing to link"))
    workspace = window.screens["case"]
    workspace.add_evidence.click()
    qtbot.waitUntil(lambda: workspace.evidence_table.rowCount() == 1, timeout=5000)
    assert workspace.evidence_table.item(0, 1).text() == "—"
    assert state.evidence.list(other.id)[0].finding_id is None


def test_close_and_delete_refused_while_a_run_is_going(ui, monkeypatch):
    window, state, case = ui
    workspace = window.screens["case"]
    messages = []
    state.message.connect(messages.append)
    monkeypatch.setattr(state.runner, "has_active_run", lambda case_id: case_id == case.id)
    workspace.close_btn.click()
    assert state.cases.get_case(case.id).is_open
    assert "still running" in messages[-1]

    monkeypatch.setattr(state.runner, "has_active_run", lambda case_id: False)
    workspace.close_btn.click()
    assert not state.cases.get_case(case.id).is_open
    monkeypatch.setattr(state.runner, "has_active_run", lambda case_id: True)
    monkeypatch.setattr(DeleteCaseDialog, "exec", lambda self: pytest.fail("must refuse before asking"))
    workspace.delete_btn.click()
    assert state.cases.list_cases() != []
    assert "still running" in messages[-1]


def test_export_report_from_screen(ui):
    window, state, case = ui
    window.navigate("reports")
    screen = window.screens["reports"]
    assert "Leads, clearly labeled (1)" == screen.inc_leads.text()
    assert "[redacted email]" in screen.preview.toPlainText()
    screen.fmt.buttons["md"].click()
    assert screen.export_btn.text() == "Export Markdown report"
    saved = screen.export()
    assert saved is not None and saved.suffix == ".md" and saved.exists()
    assert saved.parent.name == "reports" and saved.parent.parent.name == "CASE-001"
    assert "GitHub profile" in saved.read_text(encoding="utf-8")


def test_delete_requires_closed_case_and_typed_ref(ui, monkeypatch):
    window, state, case = ui
    workspace = window.screens["case"]
    assert not workspace.delete_btn.isVisible()
    workspace.close_btn.click()
    assert workspace.delete_btn.isVisible()

    def confirm(dialog):
        dialog.confirm.setText("case-00")
        assert not dialog.ok.isEnabled()
        dialog.confirm.setText(case.ref.lower())
        assert dialog.ok.isEnabled()
        return 1

    monkeypatch.setattr(DeleteCaseDialog, "exec", confirm)
    workspace.delete_btn.click()
    assert state.cases.list_cases() == []
    assert state.active_case is None
    assert window.current_key() == "dashboard"
    assert window.title_bar.case_pill.text() == "No active case"
