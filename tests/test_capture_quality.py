import unittest
from backend.services.capture_quality import CaptureQualityService


class CaptureQualityTests(unittest.TestCase):
    def test_offline_mode_marks_kernel_drops_unavailable(self):
        service = CaptureQualityService(mode="PCAP_REPLAY", interface="test.pcap")
        report = service.get_quality_report()
        self.assertEqual(report["mode"], "PCAP_REPLAY")
        kernel_ind = next(ind for ind in report["indicators"] if ind["name"] == "OS / Kernel Packet Drops")
        self.assertEqual(kernel_ind["status"], "UNAVAILABLE")
        self.assertEqual(kernel_ind["availability"], "UNAVAILABLE")
        self.assertIsNone(kernel_ind["value"])
        self.assertIn("Offline PCAP", kernel_ind["limitations"])

    def test_queue_drop_causes_degraded_overall_status(self):
        service = CaptureQualityService(mode="LIVE", interface="eth0")
        report1 = service.get_quality_report()
        self.assertEqual(report1["overall_status"], "HEALTHY")

        service.record_queue_drop(15)
        report2 = service.get_quality_report()
        self.assertEqual(report2["overall_status"], "DEGRADED")
        q_ind = next(ind for ind in report2["indicators"] if ind["name"] == "Application Queue Drops")
        self.assertEqual(q_ind["value"], 15)
        self.assertEqual(q_ind["status"], "DEGRADED")

    def test_eviction_causes_degraded_state(self):
        service = CaptureQualityService(mode="DEMO")
        service.record_flow_eviction(5)
        report = service.get_quality_report()
        self.assertEqual(report["overall_status"], "DEGRADED")
        f_ind = next(ind for ind in report["indicators"] if ind["name"] == "Flow State Evictions")
        self.assertEqual(f_ind["value"], 5)
        self.assertEqual(f_ind["status"], "DEGRADED")

    def test_kernel_drop_positive_vs_zero(self):
        service = CaptureQualityService(mode="LIVE", interface="en0")
        service.set_kernel_drops(0, supported=True)
        report_zero = service.get_quality_report()
        k_ind = next(ind for ind in report_zero["indicators"] if ind["name"] == "OS / Kernel Packet Drops")
        self.assertEqual(k_ind["status"], "HEALTHY")
        self.assertEqual(k_ind["value"], 0)

        service.set_kernel_drops(100, supported=True)
        report_pos = service.get_quality_report()
        k_ind_pos = next(ind for ind in report_pos["indicators"] if ind["name"] == "OS / Kernel Packet Drops")
        self.assertEqual(k_ind_pos["status"], "DEGRADED")
        self.assertEqual(k_ind_pos["value"], 100)
