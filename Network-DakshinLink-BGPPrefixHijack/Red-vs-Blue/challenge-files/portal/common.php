<?php
        declare(strict_types=1);
        session_start();

        function h(string $value): string {
            return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        }

        function client_ip(): string {
            return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        }

        function audit_event(string $action, array $extra = []): void {
            $event = array_merge([
                'timestamp' => gmdate('c'),
                'source_ip' => client_ip(),
                'session_user' => $_SESSION['user'] ?? null,
                'action' => $action,
            ], $extra);
            file_put_contents(
                '/var/log/carrier-portal/audit.jsonl',
                json_encode($event, JSON_UNESCAPED_SLASHES) . PHP_EOL,
                FILE_APPEND | LOCK_EX
            );
        }

        function require_auth(): void {
            if (($_SESSION['authenticated'] ?? false) !== true) {
                header('Location: /index.php');
                exit;
            }
        }

        function page_header(string $title): void {
            $brand = getenv('PORTAL_BRAND') ?: 'DakshinLink NOC Portal';
            echo '<!doctype html><html lang="en"><head><meta charset="utf-8">';
            echo '<meta name="viewport" content="width=device-width,initial-scale=1">';
            echo '<title>' . h($title) . ' - ' . h($brand) . '</title>';
            echo '<link rel="stylesheet" href="/style.css"></head><body>';
            echo '<header><div><span class="emblem">DL</span>';
            echo '<strong>' . h($brand) . '</strong></div>';
            if (($_SESSION['authenticated'] ?? false) === true) {
                echo '<nav><a href="/dashboard.php">Dashboard</a>';
                echo '<a href="/tickets.php">Tickets</a>';
                echo '<a href="/diag.php">Diagnostics</a>';
                echo '<a href="/logout.php">Logout</a></nav>';
            }
            echo '</header><main>';
        }

        function page_footer(): void {
            echo '</main><footer>Authorised network operations access only</footer></body></html>';
        }
