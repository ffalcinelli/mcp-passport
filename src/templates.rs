pub const DEFAULT_SUCCESS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Successful</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f4f7f9;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background-color: #ffffff;
            padding: 2.5rem;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.05);
            text-align: center;
            max-width: 400px;
            width: 90%;
        }
        .icon {
            background-color: #e6f4ea;
            color: #34a853;
            width: 64px;
            height: 64px;
            border-radius: 50%;
            display: flex;
            justify-content: center;
            align-items: center;
            margin: 0 auto 1.5rem;
        }
        h1 {
            color: #202124;
            font-size: 1.5rem;
            margin-bottom: 1rem;
        }
        p {
            color: #5f6368;
            line-height: 1.5;
            margin-bottom: 1.5rem;
        }
        .close-hint {
            font-size: 0.875rem;
            color: #9aa0a6;
        }
        .context-info {
            background-color: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1.5rem;
            text-align: left;
            font-size: 0.875rem;
        }
        .context-item {
            margin-bottom: 0.5rem;
            color: #374151;
        }
        .context-item:last-child {
            margin-bottom: 0;
        }
        .context-label {
            font-weight: 600;
            color: #111827;
            display: inline-block;
            width: 80px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
        </div>
        <h1>Authentication Successful</h1>
        <p>You have successfully authenticated with <strong>mcp-passport</strong>. You can now close this tab and return to your application.</p>
        
        <div class="context-info">
            <div class="context-item">
                <span class="context-label">Resource:</span> {{RESOURCE_NAME}}
            </div>
            <div class="context-item">
                <span class="context-label">Identity:</span> {{ISSUER_NAME}}
            </div>
        </div>

        <div class="close-hint">This tab can be safely closed.</div>
    </div>
</body>
</html>
"#;

pub const DEFAULT_FAILURE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Failed</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #fdf2f2;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background-color: #ffffff;
            padding: 2.5rem;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.05);
            text-align: center;
            max-width: 400px;
            width: 90%;
            border-top: 4px solid #f05252;
        }
        .icon {
            background-color: #fde8e8;
            color: #f05252;
            width: 64px;
            height: 64px;
            border-radius: 50%;
            display: flex;
            justify-content: center;
            align-items: center;
            margin: 0 auto 1.5rem;
        }
        h1 {
            color: #202124;
            font-size: 1.5rem;
            margin-bottom: 1rem;
        }
        p {
            color: #5f6368;
            line-height: 1.5;
            margin-bottom: 1.5rem;
        }
        .context-info {
            background-color: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1.5rem;
            text-align: left;
            font-size: 0.875rem;
        }
        .context-item {
            margin-bottom: 0.5rem;
            color: #374151;
        }
        .context-item:last-child {
            margin-bottom: 0;
        }
        .context-label {
            font-weight: 600;
            color: #111827;
            display: inline-block;
            width: 80px;
        }
        .error-box {
            background-color: #fef2f2;
            border: 1px solid #fee2e2;
            border-radius: 6px;
            padding: 0.75rem;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 0.8125rem;
            color: #991b1b;
            text-align: left;
            word-break: break-all;
            margin-bottom: 1.5rem;
        }
        .retry-hint {
            font-size: 0.875rem;
            color: #9aa0a6;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
        </div>
        <h1>Authentication Failed</h1>
        <p>Something went wrong during the authentication process.</p>

        <div class="context-info">
            <div class="context-item">
                <span class="context-label">Resource:</span> {{RESOURCE_NAME}}
            </div>
            <div class="context-item">
                <span class="context-label">Identity:</span> {{ISSUER_NAME}}
            </div>
        </div>

        <div class="error-box">
            {{ERROR_MESSAGE}}
        </div>
        <div class="retry-hint">Please try running the command again in your application.</div>
    </div>
</body>
</html>
"#;
