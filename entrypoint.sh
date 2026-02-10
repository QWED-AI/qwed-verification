# Fix permissions for workspace (so we can write build artifacts)
if [ -d "/github/workspace" ]; then
    # Only take ownership of the workspace
    chown -R appuser:appuser /github/workspace
fi

# Fix permissions for file commands (so we can write to GITHUB_OUTPUT, etc.)
# We use chmod 777 to allow appuser to write without taking ownership from the runner
# This avoids "Permission denied" errors for the runner on cleanup
if [ -d "/github/file_commands" ]; then
    chmod -R 777 /github/file_commands
fi

# Switch to appuser and run the main entrypoint
exec gosu appuser python /action_entrypoint.py "$@"
