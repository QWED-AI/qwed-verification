    def _is_password_context(self, tree: ast.AST, node: ast.Call) -> bool:
        """
        Check if a hash function is being used in a password context.
        Looks for password-related variable names nearby.
        """
        # Check the arguments to the hash function
        for arg in node.args:
            if isinstance(arg, ast.Call):
                # Check if it's encoding a password variable
                if isinstance(arg.func, ast.Attribute) and arg.func.attr == 'encode':
                    if isinstance(arg.func.value, ast.Name):
                        var_name = arg.func.value.id.lower()
                        if any(indicator in var_name for indicator in self.PASSWORD_INDICATORS):
                            return True
            elif isinstance(arg, ast.Name):
                var_name = arg.id.lower()
                if any(indicator in var_name for indicator in self.PASSWORD_INDICATORS):
                    return True
        
        # Also check nearby assignments in the same function/scope
        for other_node in ast.walk(tree):
            if isinstance(other_node, ast.Assign):
                for target in other_node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(indicator in var_name for indicator in self.PASSWORD_INDICATORS):
                            # Check if this hash call is in the same general area
                            return True
        
        return False
