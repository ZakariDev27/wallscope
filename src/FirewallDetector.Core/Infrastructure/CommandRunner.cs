using System.ComponentModel;
using System.Diagnostics;

namespace FirewallDetector.Core.Infrastructure;

public sealed record CommandResult(int ExitCode, string StdOut, string StdErr, bool Started, bool TimedOut)
{
    public bool Success => Started && !TimedOut && ExitCode == 0;

    public static CommandResult NotFound { get; } = new(-1, "", "command not found", Started: false, TimedOut: false);

    /// <summary>True when the output looks like a privilege problem rather than a real failure.</summary>
    public bool LooksLikePermissionDenied
    {
        get
        {
            var text = (StdErr + "\n" + StdOut).ToLowerInvariant();
            return text.Contains("permission denied")
                || text.Contains("operation not permitted")
                || text.Contains("you need to be root")
                || text.Contains("must be run as root")
                || text.Contains("access is denied")
                || text.Contains("requires elevation")
                || text.Contains("authorization failed");
        }
    }
}

/// <summary>Abstraction over process execution so providers can be tested without a real firewall.</summary>
public interface ICommandRunner
{
    Task<CommandResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct = default);
}

public sealed class ProcessCommandRunner : ICommandRunner
{
    public async Task<CommandResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var arg in arguments)
        {
            psi.ArgumentList.Add(arg);
        }

        using var process = new Process { StartInfo = psi };
        try
        {
            if (!process.Start())
            {
                return CommandResult.NotFound;
            }
        }
        catch (Win32Exception)
        {
            return CommandResult.NotFound;
        }
        catch (InvalidOperationException)
        {
            return CommandResult.NotFound;
        }

        process.StandardInput.Close();
        var stdoutTask = process.StandardOutput.ReadToEndAsync(CancellationToken.None);
        var stderrTask = process.StandardError.ReadToEndAsync(CancellationToken.None);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // Already exited between the timeout and the kill.
            }

            ct.ThrowIfCancellationRequested();
            return new CommandResult(-1, "", "timed out", Started: true, TimedOut: true);
        }

        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);
        return new CommandResult(process.ExitCode, stdout, stderr, Started: true, TimedOut: false);
    }
}
