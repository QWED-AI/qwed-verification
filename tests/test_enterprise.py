"""
Enterprise Test Cases for QWED DSL.

These tests demonstrate QWED's value for business-critical applications.
Replaces academic puzzles (Tower of Hanoi) with real-world enterprise rules.

Based on Gemini's feedback to pivot from "puzzles" to "business logic".
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from qwed_new.core.dsl.parser import QWEDLogicDSL, parse_and_validate
from qwed_new.core.dsl.compiler import compile_to_z3
from z3 import Solver, sat, unsat


class TestFinancialCompliance:
    """
    Financial rules that must be verified before execution.
    
    Examples:
    - Transaction approval thresholds
    - Risk limits
    - Audit requirements
    """
    
    def setup_method(self):
        self.parser = QWEDLogicDSL()
    
    def test_transaction_approval_threshold(self):
        """
        Rule: If transaction amount > 10,000, then requires_approval must be True.
        Use case: Preventing unauthorized large transactions.
        """
        dsl_code = "(IMPLIES (GT amount 10000) (EQ requires_approval True))"
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'
        
        z3_result = compile_to_z3(result['ast'], {
            'amount': {'type': 'Int'},
            'requires_approval': {'type': 'Bool'}
        })
        assert z3_result.success
        
        # Solve - should be SAT (rule can be satisfied)
        solver = Solver()
        solver.add(z3_result.compiled)
        assert solver.check() == sat
    
    def test_risk_exposure_limit(self):
        """
        Rule: Total exposure must not exceed risk_limit.
        AND each individual position must be < 50% of total.
        """
        dsl_code = """(AND 
            (LTE total_exposure risk_limit)
            (LT (DIV position_a total_exposure) 0.5)
            (LT (DIV position_b total_exposure) 0.5)
        )"""
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'
    
    def test_transaction_sum_equals_total(self):
        """
        Rule: Sum of line items must equal the stated total.
        Use case: Preventing financial report discrepancies.
        """
        dsl_code = "(EQ (PLUS line1 line2 line3) stated_total)"
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'
        
        z3_result = compile_to_z3(result['ast'])
        assert z3_result.success
    
    def test_margin_requirements(self):
        """
        Rule: If leverage > 10, then margin_deposited must be >= required_margin.
        """
        dsl_code = "(IMPLIES (GT leverage 10) (GTE margin_deposited required_margin))"
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'


class TestContractAnalysis:
    """
    Contract clause verification.
    Detecting contradictions in legal documents.
    """
    
    def setup_method(self):
        self.parser = QWEDLogicDSL()
    
    def test_payment_term_contradiction(self):
        """
        Scenario: Clause A says pay in 30 days. Clause B says pay in 60 days.
        For the same payment, these contradict.
        
        Expected: UNSAT (contradiction detected)
        """
        # payment_term cannot be both 30 AND 60
        dsl_code = "(AND (EQ payment_term 30) (EQ payment_term 60))"
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'
        
        z3_result = compile_to_z3(result['ast'])
        
        solver = Solver()
        solver.add(z3_result.compiled)
        # This should be UNSAT - contradiction!
        assert solver.check() == unsat
    
    def test_exclusivity_clause(self):
        """
        Rule: If exclusive_partner is True, then num_competitors must be 0.
        """
        dsl_code = "(IMPLIES (EQ exclusive_partner True) (EQ num_competitors 0))"
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'
    
    def test_termination_conditions(self):
        """
        Rule: Contract terminates if:
        - Notice period elapsed AND mutual consent
        - OR material breach occurred
        """
        dsl_code = """(OR 
            (AND (EQ notice_period_elapsed True) (EQ mutual_consent True))
            (EQ material_breach True)
        )"""
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'


class TestSupplyChain:
    """
    Supply chain constraint verification.
    Graph/routing problems as business logic.
    """
    
    def setup_method(self):
        self.parser = QWEDLogicDSL()
    
    def test_inventory_constraints(self):
        """
        Rule: Shipped quantity cannot exceed available inventory.
        """
        dsl_code = "(LTE shipped_qty available_inventory)"
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'
    
    def test_delivery_routing(self):
        """
        Rule: If priority_shipping is True, then delivery_days must be <= 2.
        """
        dsl_code = "(IMPLIES (EQ priority_shipping True) (LTE delivery_days 2))"
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'
    
    def test_warehouse_capacity(self):
        """
        Rule: Total items across all zones <= warehouse_capacity.
        """
        dsl_code = "(LTE (PLUS zone_a_items zone_b_items zone_c_items) warehouse_capacity)"
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'


class TestAccessControl:
    """
    Access control and authorization rules.
    RBAC (Role-Based Access Control) verification.
    """
    
    def setup_method(self):
        self.parser = QWEDLogicDSL()
    
    def test_admin_access(self):
        """
        Rule: Access is granted if user is admin OR has explicit permission.
        """
        dsl_code = "(IFF (EQ access_granted True) (OR (EQ is_admin True) (EQ has_permission True)))"
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'
    
    def test_sensitive_data_access(self):
        """
        Rule: Sensitive data access requires:
        - Security clearance >= required_level
        - AND access_hours within allowed range
        """
        dsl_code = """(AND 
            (GTE security_clearance required_level)
            (AND (GTE access_hour 9) (LTE access_hour 17))
        )"""
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'
    
    def test_separation_of_duties(self):
        """
        Rule: User who creates a request cannot approve it.
        """
        dsl_code = "(IMPLIES (EQ creator user_id) (NEQ approver user_id))"
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'


class TestAgentSafety:
    """
    AI Agent safety constraints.
    Gate dangerous operations before execution.
    """
    
    def setup_method(self):
        self.parser = QWEDLogicDSL()
    
    def test_budget_limit(self):
        """
        Rule: Agent spending must not exceed budget.
        """
        dsl_code = "(LTE current_spending budget_limit)"
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'
    
    def test_action_authorization(self):
        """
        Rule: Destructive actions require human approval.
        """
        dsl_code = "(IMPLIES (EQ action_type destructive) (EQ human_approved True))"
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'
    
    def test_rate_limiting(self):
        """
        Rule: Requests per minute must be <= rate_limit.
        """
        dsl_code = "(LTE requests_per_minute rate_limit)"
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'
    
    def test_safe_output_bounds(self):
        """
        Rule: Agent's numerical output must be within expected bounds.
        Use case: Catching hallucinated extreme values.
        """
        dsl_code = "(AND (GTE output_value min_expected) (LTE output_value max_expected))"
        
        result = parse_and_validate(dsl_code)
        assert result['status'] == 'SUCCESS'


# Run tests directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
