import unittest
from unittest.mock import MagicMock, patch
from qwed_new.providers.auto_shift import AutoShiftProvider
from qwed_new.core.schemas import MathVerificationTask

class TestAutoShift(unittest.TestCase):
    def setUp(self):
        # Create mocks for the providers
        self.mock_azure = MagicMock()
        self.mock_anthropic = MagicMock()

    def test_primary_success(self):
        """Test that primary provider is used when it succeeds."""
        # Setup primary to succeed
        self.mock_azure.translate.return_value = MathVerificationTask(expression="2+2", claimed_answer=4.0)
        
        # Patch the provider classes to return our mocks
        with patch('qwed_new.providers.auto_shift.AzureOpenAIProvider', return_value=self.mock_azure), \
             patch('qwed_new.providers.auto_shift.AnthropicProvider', return_value=self.mock_anthropic):
            
            provider = AutoShiftProvider()
            result = provider.translate("Calculate 2+2")
            
            # Verify primary was called
            self.mock_azure.translate.assert_called_once()
            # Verify secondary was NOT called
            self.mock_anthropic.translate.assert_not_called()
            self.assertEqual(result.expression, "2+2")

    def test_failover_to_secondary(self):
        """Test that secondary provider is used when primary fails."""
        # Setup primary to fail
        self.mock_azure.translate.side_effect = Exception("Azure Timeout")
        # Setup secondary to succeed
        self.mock_anthropic.translate.return_value = MathVerificationTask(expression="3+3", claimed_answer=6.0)
        
        with patch('qwed_new.providers.auto_shift.AzureOpenAIProvider', return_value=self.mock_azure), \
             patch('qwed_new.providers.auto_shift.AnthropicProvider', return_value=self.mock_anthropic):
            
            provider = AutoShiftProvider()
            result = provider.translate("Calculate 3+3")
            
            # Verify primary was called (and failed)
            self.mock_azure.translate.assert_called_once()
            # Verify secondary WAS called
            self.mock_anthropic.translate.assert_called_once()
            self.assertEqual(result.expression, "3+3")

    def test_both_fail(self):
        """Test that exception is raised when both fail."""
        self.mock_azure.translate.side_effect = Exception("Azure Timeout")
        self.mock_anthropic.translate.side_effect = Exception("Anthropic Error")
        
        with patch('qwed_new.providers.auto_shift.AzureOpenAIProvider', return_value=self.mock_azure), \
             patch('qwed_new.providers.auto_shift.AnthropicProvider', return_value=self.mock_anthropic):
            
            provider = AutoShiftProvider()
            
            with self.assertRaises(Exception):
                provider.translate("Calculate 4+4")

if __name__ == '__main__':
    unittest.main()
