"""
detection/decision_engine.py
AI Firewall — Final decision engine.

Combines the Random Forest model prediction with the behavioural
risk score from RiskEngine to produce a per-flow firewall action.
"""


class DecisionEngine:
    """
    Decision thresholds
    -------------------
    BLOCK   : RF predicts attack  OR  risk >= 0.70
    MONITOR : risk >= 0.40 (and RF predicts benign)
    ALLOW   : everything else
    """

    BLOCK_RISK_THRESHOLD   = 0.70
    MONITOR_RISK_THRESHOLD = 0.40

    def decide(self, rf_prediction: int, risk_score: float) -> str:
        """
        Parameters
        ----------
        rf_prediction : int
            Output of the trained Random Forest model.
            1 = attack / malicious,  0 = benign / normal.

        risk_score : float  (0.0 – 1.0)
            Behavioural risk score from RiskEngine.calculate_risk().

        Returns
        -------
        str
            "BLOCK"   — drop traffic and add firewall rule
            "MONITOR" — log and flag for review
            "ALLOW"   — pass through normally
        """
        if rf_prediction == 1 or risk_score >= self.BLOCK_RISK_THRESHOLD:
            return "BLOCK"
        if risk_score >= self.MONITOR_RISK_THRESHOLD:
            return "MONITOR"
        return "ALLOW"
