class RiskEngine:
    def calculate_risk(
        self,
        syn_count,
        unique_ports,
        packets_per_second,
        rst_count
    ):
        risk = 0.0
        if syn_count >= 20:
            risk += 0.30
        elif syn_count >= 10:
            risk += 0.15

        
        if unique_ports >= 20:
            risk += 0.35
        elif unique_ports >= 10:
            risk += 0.20

        
        if packets_per_second >= 50:
            risk += 0.20
        elif packets_per_second >= 20:
            risk += 0.10

        
        if rst_count >= 20:
            risk += 0.15

        return min(risk, 1.0)