"""
tests/test_detection_rules.py

Unit test validation for Stage 3B / Stage 4 / Stage 5.1 rule-based threat detection,
investigation, and explainable severity classification engine.
Covers positive triggers, negative non-triggers, boundary conditions,
severity level escalation, custom thresholds, missing/incomplete evidence,
severity count reconciliation, sequence verification, multi-rule scenarios,
Rule B/C session qualification, Rule E timing, evidence schemas,
password masking, and demo session consistency.
"""

import unittest
import pandas as pd
from utils.detection_rules import (
    mask_password,
    classify_rule_a_severity,
    classify_rule_b_severity,
    classify_rule_c_severity,
    classify_rule_d_severity,
    classify_rule_e_severity,
    detect_repeated_auth_failures,
    detect_password_spraying,
    detect_credential_pair_reuse,
    detect_auth_success_after_failures,
    detect_post_auth_commands,
    run_all_detection_rules,
    correlate_incidents,
    Incident,
)
from utils.data_loader import load_data


class TestDetectionRules(unittest.TestCase):

    def test_mask_password(self):
        self.assertEqual(mask_password(""), "(empty)")
        self.assertEqual(mask_password(None), "(empty)")
        self.assertEqual(mask_password("ab"), "**")
        self.assertEqual(mask_password("123456"), "1****6")
        self.assertEqual(mask_password("password"), "p******d")
        self.assertEqual(mask_password("admin"), "a***n")

    def test_severity_classification_escalation(self):
        # Rule A severity tests (t=10)
        self.assertEqual(classify_rule_a_severity(30, 10)[0], "Critical")
        self.assertEqual(classify_rule_a_severity(35, 10)[0], "Critical")
        self.assertEqual(classify_rule_a_severity(20, 10)[0], "High")
        self.assertEqual(classify_rule_a_severity(29, 10)[0], "High")
        self.assertEqual(classify_rule_a_severity(10, 10)[0], "Medium")
        self.assertEqual(classify_rule_a_severity(19, 10)[0], "Medium")
        self.assertEqual(classify_rule_a_severity(9, 10)[0], "Low")

        # Rule B severity tests (t=5)
        self.assertEqual(classify_rule_b_severity(10, 5)[0], "High")
        self.assertEqual(classify_rule_b_severity(15, 5)[0], "High")
        self.assertEqual(classify_rule_b_severity(5, 5)[0], "Medium")
        self.assertEqual(classify_rule_b_severity(9, 5)[0], "Medium")
        self.assertEqual(classify_rule_b_severity(4, 5)[0], "Low")

        # Rule C severity tests (t=3)
        self.assertEqual(classify_rule_c_severity(6, 3)[0], "High")
        self.assertEqual(classify_rule_c_severity(12, 3)[0], "High")
        self.assertEqual(classify_rule_c_severity(3, 3)[0], "Medium")
        self.assertEqual(classify_rule_c_severity(5, 3)[0], "Medium")
        self.assertEqual(classify_rule_c_severity(2, 3)[0], "Low")

        # Rule D & E default severities
        self.assertEqual(classify_rule_d_severity()[0], "Medium")
        self.assertEqual(classify_rule_e_severity(3)[0], "Medium")

    def test_custom_thresholds_severity_escalation(self):
        # Custom threshold t=4 for Rule A: 8 is High (2x), 12 is Critical (3x)
        self.assertEqual(classify_rule_a_severity(12, 4)[0], "Critical")
        self.assertEqual(classify_rule_a_severity(8, 4)[0], "High")
        self.assertEqual(classify_rule_a_severity(4, 4)[0], "Medium")

        # Custom threshold t=10 for Rule B: 20 is High, 10 is Medium
        self.assertEqual(classify_rule_b_severity(20, 10)[0], "High")
        self.assertEqual(classify_rule_b_severity(10, 10)[0], "Medium")

        # Custom threshold t=8 for Rule C: 16 is High, 8 is Medium
        self.assertEqual(classify_rule_c_severity(16, 8)[0], "High")
        self.assertEqual(classify_rule_c_severity(8, 8)[0], "Medium")

    def test_missing_and_incomplete_evidence(self):
        empty_sess = pd.DataFrame()
        empty_creds = pd.DataFrame()
        empty_cmds = pd.DataFrame()

        ra = detect_repeated_auth_failures(empty_sess, empty_creds)
        self.assertEqual(ra.matched_records_count, 0)
        self.assertTrue(ra.evidence_df.empty)
        self.assertIn("Severity", ra.evidence_df.columns)

        rb = detect_password_spraying(empty_creds)
        self.assertEqual(rb.matched_records_count, 0)
        self.assertTrue(rb.evidence_df.empty)
        self.assertIn("Severity", rb.evidence_df.columns)

        rc = detect_credential_pair_reuse(empty_creds)
        self.assertEqual(rc.matched_records_count, 0)
        self.assertTrue(rc.evidence_df.empty)
        self.assertIn("Severity", rc.evidence_df.columns)

        rd = detect_auth_success_after_failures(empty_sess, empty_creds)
        self.assertEqual(rd.matched_records_count, 0)
        self.assertTrue(rd.evidence_df.empty)
        self.assertIn("Severity", rd.evidence_df.columns)

        re = detect_post_auth_commands(empty_sess, empty_cmds)
        self.assertEqual(re.matched_records_count, 0)
        self.assertTrue(re.evidence_df.empty)
        self.assertIn("Severity", re.evidence_df.columns)

    def test_rule_a_repeated_auth_failures(self):
        # Trigger case: 12 failures >= 10 (Medium), 25 failures (High), 35 failures (Critical)
        sess_df = pd.DataFrame([
            {"session_id": "s1", "src_ip_identifier": "ip_a", "failed_logins": 12, "start_time": "2020-02-07 10:00:00", "end_time": "2020-02-07 10:01:00"},
            {"session_id": "s2", "src_ip_identifier": "ip_b", "failed_logins": 25, "start_time": "2020-02-07 10:00:00", "end_time": "2020-02-07 10:01:00"},
            {"session_id": "s3", "src_ip_identifier": "ip_c", "failed_logins": 35, "start_time": "2020-02-07 10:00:00", "end_time": "2020-02-07 10:01:00"},
            {"session_id": "s4", "src_ip_identifier": "ip_d", "failed_logins": 9, "start_time": "2020-02-07 10:00:00", "end_time": "2020-02-07 10:01:00"}, # Non-trigger
        ])
        creds_df = pd.DataFrame([
            {"session_id": "s1", "username": "root"},
            {"session_id": "s2", "username": "admin"},
            {"session_id": "s3", "username": "oracle"},
        ])
        res = detect_repeated_auth_failures(sess_df, creds_df, threshold_failures=10)
        self.assertEqual(res.matched_records_count, 3)
        self.assertEqual(res.unique_affected_attackers, 3)
        self.assertEqual(res.unique_affected_sessions, 3)
        self.assertIn("s1", res.affected_session_ids)
        self.assertNotIn("s4", res.affected_session_ids)

        # Check severity escalation
        s3_row = res.evidence_df[res.evidence_df["Session ID"] == "s3"].iloc[0]
        s2_row = res.evidence_df[res.evidence_df["Session ID"] == "s2"].iloc[0]
        s1_row = res.evidence_df[res.evidence_df["Session ID"] == "s1"].iloc[0]
        self.assertEqual(s3_row["Severity"], "Critical")
        self.assertEqual(s2_row["Severity"], "High")
        self.assertEqual(s1_row["Severity"], "Medium")

        # Verify schema
        self.assertIn("Severity", res.evidence_df.columns)
        self.assertIn("Severity Reason", res.evidence_df.columns)
        self.assertIn("Active Threshold", res.evidence_df.columns)
        self.assertIn("Successful Logins", res.evidence_df.columns)

    def test_rule_b_password_spraying(self):
        # Trigger case: ip_spray uses "Winter2020" on 10 distinct usernames (High at t=5)
        creds = []
        for i in range(10):
            creds.append({
                "src_ip_identifier": "ip_spray",
                "session_id": f"s_spray_{i}",
                "username": f"user_{i}",
                "password": "Winter2020",
                "timestamp": f"2020-02-07 10:0{i}:00"
            })
        # Add another attacker with 5 distinct users (Medium at t=5)
        for i in range(5):
            creds.append({
                "src_ip_identifier": "ip_med",
                "session_id": f"s_med_{i}",
                "username": f"user_{i}",
                "password": "Spring2020",
                "timestamp": f"2020-02-07 10:0{i}:00"
            })
        # Add a non-spraying password for the same attacker in another session
        creds.append({
            "src_ip_identifier": "ip_spray",
            "session_id": "s_other_pwd",
            "username": "root",
            "password": "DifferentPassword",
            "timestamp": "2020-02-07 10:10:00"
        })
        # Non-trigger case: only 4 usernames
        for i in range(4):
            creds.append({
                "src_ip_identifier": "ip_normal",
                "session_id": f"s_norm_{i}",
                "username": f"user_{i}",
                "password": "SecretPassword",
                "timestamp": f"2020-02-07 11:0{i}:00"
            })

        creds_df = pd.DataFrame(creds)
        res = detect_password_spraying(creds_df, threshold_distinct_usernames=5)
        self.assertEqual(res.matched_records_count, 2)
        self.assertEqual(res.unique_affected_attackers, 2)
        self.assertIn("ip_spray", res.affected_attacker_ids)
        self.assertIn("ip_med", res.affected_attacker_ids)
        self.assertNotIn("ip_normal", res.affected_attacker_ids)

        # Check severity escalation
        row_spray = res.evidence_df[res.evidence_df["Attacker Identifier"] == "ip_spray"].iloc[0]
        row_med = res.evidence_df[res.evidence_df["Attacker Identifier"] == "ip_med"].iloc[0]
        self.assertEqual(row_spray["Severity"], "High")
        self.assertEqual(row_med["Severity"], "Medium")

        # Crucial Rule B Session Qualification: s_spray_0..9 should be included, s_other_pwd must NOT be included
        for i in range(10):
            self.assertIn(f"s_spray_{i}", res.affected_session_ids)
        self.assertNotIn("s_other_pwd", res.affected_session_ids)

        # Verify schema
        self.assertIn("Severity", res.evidence_df.columns)
        self.assertIn("Severity Reason", res.evidence_df.columns)
        self.assertIn("Affected Sessions", res.evidence_df.columns)
        self.assertIn("Raw Password", res.evidence_df.columns)
        self.assertIn("Masked Password", res.evidence_df.columns)

    def test_rule_c_credential_pair_reuse(self):
        # Trigger case 1: ("root", "admin") tested by 6 distinct attackers across 6 sessions (High at t=3)
        creds = []
        for i in range(6):
            creds.append({"src_ip_identifier": f"ip_high_{i}", "session_id": f"s_h_{i}", "username": "root", "password": "admin", "login_success": False})
        # Trigger case 2: ("admin", "password") tested by 3 distinct attackers (Medium at t=3)
        for i in range(3):
            creds.append({"src_ip_identifier": f"ip_med_{i}", "session_id": f"s_m_{i}", "username": "admin", "password": "password", "login_success": False})

        creds_df = pd.DataFrame(creds)
        res = detect_credential_pair_reuse(creds_df, threshold_distinct_attackers=3)
        self.assertEqual(res.matched_records_count, 2)
        
        row_root = res.evidence_df[res.evidence_df["Username"] == "root"].iloc[0]
        row_admin = res.evidence_df[res.evidence_df["Username"] == "admin"].iloc[0]
        self.assertEqual(row_root["Severity"], "High")
        self.assertEqual(row_admin["Severity"], "Medium")

        self.assertIn("Severity", res.evidence_df.columns)
        self.assertIn("Severity Reason", res.evidence_df.columns)

    def test_rule_d_auth_success_after_failures(self):
        sess_df = pd.DataFrame([
            {"session_id": "s_mixed", "src_ip_identifier": "ip_d", "failed_logins": 3, "successful_logins": 1},
        ])
        creds_df = pd.DataFrame([
            {"session_id": "s_mixed", "timestamp": pd.to_datetime("2020-02-07 10:00:01"), "login_success": False},
            {"session_id": "s_mixed", "timestamp": pd.to_datetime("2020-02-07 10:00:03"), "login_success": True},
        ])
        res = detect_auth_success_after_failures(sess_df, creds_df)
        self.assertEqual(res.matched_records_count, 1)
        self.assertEqual(res.evidence_df.iloc[0]["Severity"], "Medium")
        self.assertIn("Severity", res.evidence_df.columns)
        self.assertIn("Severity Reason", res.evidence_df.columns)

    def test_rule_e_post_auth_commands(self):
        sess_df = pd.DataFrame([
            {"session_id": "s_cmd", "src_ip_identifier": "ip_e", "successful_logins": 1, "command_count": 2, "duration": 15.5},
        ])
        cmds_df = pd.DataFrame([
            {"session_id": "s_cmd", "command": "uname -a", "timestamp": pd.to_datetime("2020-02-07 10:00:05.500")},
        ])
        creds_df = pd.DataFrame([
            {"session_id": "s_cmd", "login_success": True, "timestamp": pd.to_datetime("2020-02-07 10:00:05.000")},
        ])
        res = detect_post_auth_commands(sess_df, cmds_df, credentials=creds_df)
        self.assertEqual(res.matched_records_count, 1)
        self.assertEqual(res.evidence_df.iloc[0]["Severity"], "Medium")
        self.assertIn("Severity", res.evidence_df.columns)
        self.assertIn("Severity Reason", res.evidence_df.columns)

    def test_severity_count_reconciliation(self):
        sess_df = pd.DataFrame([
            {"session_id": "s1", "src_ip_identifier": "ip1", "failed_logins": 30, "successful_logins": 1, "command_count": 2, "duration": 30.0},
        ])
        creds_df = pd.DataFrame([
            {"session_id": "s1", "src_ip_identifier": "ip1", "username": "root", "password": "pwd", "login_success": False, "timestamp": pd.to_datetime("2020-02-07 10:00:01")},
            {"session_id": "s1", "src_ip_identifier": "ip1", "username": "root", "password": "pwd", "login_success": True, "timestamp": pd.to_datetime("2020-02-07 10:00:02")},
        ])
        cmds_df = pd.DataFrame([
            {"session_id": "s1", "command": "id", "timestamp": pd.to_datetime("2020-02-07 10:00:03")},
        ])
        # t=10: s1 triggers Rule A with 30 failures -> Critical!
        # Rule D -> Medium
        # Rule E -> Medium
        result = run_all_detection_rules(sess_df, creds_df, cmds_df, threshold_failures=10, threshold_distinct_usernames=5, threshold_distinct_attackers=3)
        summary = result["summary"]
        sev_counts = summary["severity_counts"]
        
        self.assertEqual(sev_counts["Critical"], 1)
        self.assertEqual(sev_counts["Medium"], 2)
        self.assertEqual(sev_counts["High"], 0)
        self.assertEqual(sev_counts["Low"], 0)
        # Sum of severities equals total matched records
        self.assertEqual(sum(sev_counts.values()), summary["total_matching_records"])

    def test_demo_mode_session_consistency_and_severity(self):
        demo = load_data("demo")
        events = demo["events"]
        sessions = demo["sessions"]
        credentials = demo["credentials"]
        commands = demo["commands"]

        res = run_all_detection_rules(sessions, credentials, commands)
        self.assertEqual(res["summary"]["total_rules"], 5)
        self.assertGreater(res["summary"]["unique_affected_sessions"], 0)
        self.assertIn("severity_counts", res["summary"])
        
        # Verify severity sum equals total matched records in demo mode
        self.assertEqual(sum(res["summary"]["severity_counts"].values()), res["summary"]["total_matching_records"])


    def test_same_session_grouping(self):
        # Two findings in the exact same session (Rule D and Rule E)
        sess_df = pd.DataFrame([
            {"session_id": "sess_shared", "src_ip_identifier": "att_1", "failed_logins": 5, "successful_logins": 1, "command_count": 3, "duration": 40.0, "start_time": pd.to_datetime("2024-03-01 10:00:00"), "end_time": pd.to_datetime("2024-03-01 10:00:40")},
        ])
        creds_df = pd.DataFrame([
            {"session_id": "sess_shared", "src_ip_identifier": "att_1", "username": "admin", "password": "pwd", "login_success": False, "timestamp": pd.to_datetime("2024-03-01 10:00:05")},
            {"session_id": "sess_shared", "src_ip_identifier": "att_1", "username": "admin", "password": "pwd", "login_success": True, "timestamp": pd.to_datetime("2024-03-01 10:00:10")},
        ])
        cmds_df = pd.DataFrame([
            {"session_id": "sess_shared", "command": "uname -a", "timestamp": pd.to_datetime("2024-03-01 10:00:12")},
        ])
        res = run_all_detection_rules(sess_df, creds_df, cmds_df, threshold_failures=10, threshold_distinct_usernames=5, threshold_distinct_attackers=3)
        # Should trigger Rule D and Rule E
        self.assertEqual(res["rules"]["RULE_D"].matched_records_count, 1)
        self.assertEqual(res["rules"]["RULE_E"].matched_records_count, 1)
        
        incidents = res["incidents"]
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.finding_count, 2)
        self.assertEqual(inc.session_ids, ["sess_shared"])
        self.assertEqual(inc.attacker_ids, ["att_1"])
        self.assertIn("Post-Authentication Command Activity", inc.rules_involved)
        self.assertIn("Authentication Success After Failures", inc.rules_involved)
        self.assertIn("sess_shared", inc.correlation_reason)

    def test_same_attacker_within_correlation_window(self):
        # Two sessions for att_1, spaced 15 minutes apart (<= 30 min default window)
        sess_df = pd.DataFrame([
            {"session_id": "sess_w1", "src_ip_identifier": "att_alpha", "failed_logins": 10, "successful_logins": 0, "command_count": 0, "duration": 20.0, "start_time": pd.to_datetime("2024-03-01 10:00:00"), "end_time": pd.to_datetime("2024-03-01 10:00:20")},
            {"session_id": "sess_w2", "src_ip_identifier": "att_alpha", "failed_logins": 10, "successful_logins": 0, "command_count": 0, "duration": 20.0, "start_time": pd.to_datetime("2024-03-01 10:15:00"), "end_time": pd.to_datetime("2024-03-01 10:15:20")},
        ])
        creds_df = pd.DataFrame([
            {"session_id": "sess_w1", "src_ip_identifier": "att_alpha", "username": f"u{i}", "password": "p", "login_success": False, "timestamp": pd.to_datetime(f"2024-03-01 10:00:{i:02d}")} for i in range(10)
        ] + [
            {"session_id": "sess_w2", "src_ip_identifier": "att_alpha", "username": f"u{i}", "password": "p", "login_success": False, "timestamp": pd.to_datetime(f"2024-03-01 10:15:{i:02d}")} for i in range(10)
        ])
        cmds_df = pd.DataFrame()
        
        # Rule A triggers for both sessions; both belong to att_alpha and are 15 mins apart
        res = run_all_detection_rules(sess_df, creds_df, cmds_df, threshold_failures=10, threshold_distinct_usernames=20, threshold_distinct_attackers=20, correlation_time_window_minutes=30)
        self.assertEqual(res["rules"]["RULE_A"].matched_records_count, 2)
        
        incidents = res["incidents"]
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.finding_count, 2)
        self.assertEqual(set(inc.session_ids), {"sess_w1", "sess_w2"})
        self.assertEqual(inc.attacker_ids, ["att_alpha"])
        self.assertIn("30m window", inc.correlation_reason)

    def test_same_attacker_outside_correlation_window(self):
        # Two sessions for att_beta, spaced 60 minutes apart (> 30 min window)
        sess_df = pd.DataFrame([
            {"session_id": "sess_gap1", "src_ip_identifier": "att_beta", "failed_logins": 10, "successful_logins": 0, "command_count": 0, "duration": 20.0, "start_time": pd.to_datetime("2024-03-01 10:00:00"), "end_time": pd.to_datetime("2024-03-01 10:00:20")},
            {"session_id": "sess_gap2", "src_ip_identifier": "att_beta", "failed_logins": 10, "successful_logins": 0, "command_count": 0, "duration": 20.0, "start_time": pd.to_datetime("2024-03-01 11:30:00"), "end_time": pd.to_datetime("2024-03-01 11:30:20")},
        ])
        creds_df = pd.DataFrame([
            {"session_id": "sess_gap1", "src_ip_identifier": "att_beta", "username": f"u{i}", "password": "p", "login_success": False, "timestamp": pd.to_datetime(f"2024-03-01 10:00:{i:02d}")} for i in range(10)
        ] + [
            {"session_id": "sess_gap2", "src_ip_identifier": "att_beta", "username": f"u{i}", "password": "p", "login_success": False, "timestamp": pd.to_datetime(f"2024-03-01 11:30:{i:02d}")} for i in range(10)
        ])
        cmds_df = pd.DataFrame()
        
        res = run_all_detection_rules(sess_df, creds_df, cmds_df, threshold_failures=10, threshold_distinct_usernames=20, threshold_distinct_attackers=20, correlation_time_window_minutes=30)
        self.assertEqual(res["rules"]["RULE_A"].matched_records_count, 2)
        
        incidents = res["incidents"]
        # Must be 2 separate incidents because gap is 90 mins (> 30 min window)
        self.assertEqual(len(incidents), 2)
        self.assertEqual(incidents[0].finding_count, 1)
        self.assertEqual(incidents[1].finding_count, 1)

    def test_different_attackers_remain_separate(self):
        # Two sessions at the exact same timestamp but belonging to DIFFERENT attackers
        sess_df = pd.DataFrame([
            {"session_id": "sess_att1", "src_ip_identifier": "att_one", "failed_logins": 10, "successful_logins": 0, "command_count": 0, "duration": 20.0, "start_time": pd.to_datetime("2024-03-01 10:00:00"), "end_time": pd.to_datetime("2024-03-01 10:00:20")},
            {"session_id": "sess_att2", "src_ip_identifier": "att_two", "failed_logins": 10, "successful_logins": 0, "command_count": 0, "duration": 20.0, "start_time": pd.to_datetime("2024-03-01 10:00:00"), "end_time": pd.to_datetime("2024-03-01 10:00:20")},
        ])
        creds_df = pd.DataFrame([
            {"session_id": "sess_att1", "src_ip_identifier": "att_one", "username": f"u{i}", "password": "p", "login_success": False, "timestamp": pd.to_datetime("2024-03-01 10:00:05")} for i in range(10)
        ] + [
            {"session_id": "sess_att2", "src_ip_identifier": "att_two", "username": f"u{i}", "password": "p", "login_success": False, "timestamp": pd.to_datetime("2024-03-01 10:00:05")} for i in range(10)
        ])
        cmds_df = pd.DataFrame()
        
        res = run_all_detection_rules(sess_df, creds_df, cmds_df, threshold_failures=10, threshold_distinct_usernames=20, threshold_distinct_attackers=20)
        incidents = res["incidents"]
        self.assertEqual(len(incidents), 2)
        att_sets = [set(inc.attacker_ids) for inc in incidents]
        self.assertIn({"att_one"}, att_sets)
        self.assertIn({"att_two"}, att_sets)

    def test_missing_identifiers_and_timestamps(self):
        # Findings with missing timestamps or missing attacker IDs must not crash and remain separate
        fake_rules = {
            "RULE_A": type("MockResult", (), {
                "rule_id": "RULE_A", "rule_name": "Mock Rule A",
                "evidence_df": pd.DataFrame([
                    {"Severity": "Medium", "Severity Reason": "No TS", "Session ID": "s_nots", "Attacker Identifier": "att_x"}
                ])
            })(),
            "RULE_B": type("MockResult", (), {
                "rule_id": "RULE_B", "rule_name": "Mock Rule B",
                "evidence_df": pd.DataFrame([
                    {"Severity": "High", "Severity Reason": "No Attacker", "Masked Password": "p****d", "Distinct Usernames": 6}
                ])
            })(),
        }
        res = correlate_incidents({"rules": fake_rules}, sessions=None, time_window_minutes=30)
        self.assertEqual(res["summary"]["total_incidents"], 2)
        self.assertEqual(res["summary"]["total_findings_reconciled"], 2)
        for inc in res["incidents"]:
            self.assertEqual(inc.finding_count, 1)

    def test_incident_severity_aggregation(self):
        # Incident with findings of Medium and Critical must inherit Critical
        sess_df = pd.DataFrame([
            {"session_id": "sess_crit", "src_ip_identifier": "att_crit", "failed_logins": 30, "successful_logins": 1, "command_count": 2, "duration": 35.0, "start_time": pd.to_datetime("2024-03-01 10:00:00"), "end_time": pd.to_datetime("2024-03-01 10:00:35")},
        ])
        creds_df = pd.DataFrame([
            {"session_id": "sess_crit", "src_ip_identifier": "att_crit", "username": "admin", "password": "pwd", "login_success": False, "timestamp": pd.to_datetime("2024-03-01 10:00:05")} for _ in range(30)
        ] + [
            {"session_id": "sess_crit", "src_ip_identifier": "att_crit", "username": "admin", "password": "pwd", "login_success": True, "timestamp": pd.to_datetime("2024-03-01 10:00:10")}
        ])
        cmds_df = pd.DataFrame([
            {"session_id": "sess_crit", "command": "id", "timestamp": pd.to_datetime("2024-03-01 10:00:12")},
        ])
        # Rule A triggers with 30 failures (threshold 10 -> 3x -> Critical)
        # Rule D triggers -> Medium
        # Rule E triggers -> Medium
        res = run_all_detection_rules(sess_df, creds_df, cmds_df, threshold_failures=10, threshold_distinct_usernames=50, threshold_distinct_attackers=50)
        self.assertEqual(len(res["incidents"]), 1)
        inc = res["incidents"][0]
        self.assertEqual(inc.severity, "Critical")
        self.assertEqual(inc.finding_count, 3)

    def test_finding_count_reconciliation_and_masking(self):
        demo = load_data("demo")
        res = run_all_detection_rules(demo["sessions"], demo["credentials"], demo["commands"])
        summary = res["summary"]
        inc_summary = res["incident_summary"]
        
        # Reconciliation: total findings in incidents equals total matched records across rules
        self.assertEqual(inc_summary["total_findings_reconciled"], summary["total_matching_records"])
        self.assertEqual(sum(inc.finding_count for inc in res["incidents"]), summary["total_matching_records"])
        
        # Password masking check: no raw password exposed in incidents_df or findings
        inc_df = res["incidents_df"]
        self.assertNotIn("Raw Password", inc_df.columns)
        self.assertNotIn("raw_password", inc_df.columns)
        self.assertNotIn("password", inc_df.columns)
        
        for inc in res["incidents"]:
            for f in inc.findings:
                self.assertNotIn("Raw Password", f)
                self.assertNotIn("raw_password", f)


if __name__ == "__main__":
    unittest.main()

