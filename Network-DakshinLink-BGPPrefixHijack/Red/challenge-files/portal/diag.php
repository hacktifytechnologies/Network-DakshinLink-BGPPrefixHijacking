<?php
        declare(strict_types=1);
        require_once __DIR__ . '/common.php';
        require_auth();
        ignore_user_abort(true);
        set_time_limit(0);
        $output = '';
        $error = '';
        $defaultCheck = base64_encode('frr');
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $encoded = (string)($_POST['check'] ?? '');
            $decoded = base64_decode($encoded, true);
            if ($decoded === false || strlen($decoded) > 4096) {
                $error = 'Invalid diagnostic request.';
                audit_event('diagnostic_rejected', ['check_b64' => $encoded]);
            } else {
                $target = getenv('R1_MGMT_IP') ?: '';
                $remoteCommand = 'ps aux | grep ' . $decoded;
                audit_event('diagnostic_execute', [
                    'check_b64' => $encoded,
                    'decoded_check' => $decoded,
                    'router' => $target,
                ]);
                $command = [
                    '/usr/bin/ssh',
                    '-i', '/var/www/.ssh/id_ed25519',
                    '-o', 'BatchMode=yes',
                    '-o', 'ConnectTimeout=5',
                    '-o', 'StrictHostKeyChecking=yes',
                    'root@' . $target,
                    $remoteCommand,
                ];
                $spec = [
                    0 => ['pipe', 'r'],
                    1 => ['pipe', 'w'],
                    2 => ['pipe', 'w'],
                ];
                $process = proc_open($command, $spec, $pipes);
                if (is_resource($process)) {
                    fclose($pipes[0]);
                    $stdout = stream_get_contents($pipes[1]);
                    $stderr = stream_get_contents($pipes[2]);
                    fclose($pipes[1]);
                    fclose($pipes[2]);
                    $status = proc_close($process);
                    $output = trim((string)$stdout . (string)$stderr);
                    audit_event('diagnostic_complete', ['exit_status' => $status]);
                } else {
                    $error = 'Router diagnostic transport unavailable.';
                    audit_event('diagnostic_transport_failure');
                }
            }
        }
        page_header('Diagnostics');
        ?>
        <section class="hero compact">
          <p class="eyebrow">REMOTE ROUTER CHECK</p>
          <h1>Diagnostics</h1>
          <p>The support licence is expired. Status verification remains available for operational continuity.</p>
        </section>
        <section class="card">
          <h2>FRRouting process check</h2>
          <?php if ($error !== ''): ?><p class="error"><?= h($error) ?></p><?php endif; ?>
          <form method="post">
            <input type="hidden" name="check" value="<?= h($defaultCheck) ?>">
            <button type="submit">Verify status</button>
          </form>
          <?php if ($output !== ''): ?><pre><?= h($output) ?></pre><?php endif; ?>
        </section>
        <?php page_footer(); ?>
