<?php
        declare(strict_types=1);
        require_once __DIR__ . '/common.php';
        if (($_SESSION['authenticated'] ?? false) === true) {
            header('Location: /dashboard.php');
            exit;
        }
        $error = '';
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $username = (string)($_POST['username'] ?? '');
            $password = (string)($_POST['password'] ?? '');
            $serial = getenv('DEVICE_SERIAL') ?: '';
            if (hash_equals('admin', $username) && $serial !== '' && hash_equals($serial, $password)) {
                session_regenerate_id(true);
                $_SESSION['authenticated'] = true;
                $_SESSION['user'] = 'admin';
                audit_event('login_success', ['username' => $username]);
                header('Location: /dashboard.php');
                exit;
            }
            audit_event('login_failure', ['username' => $username]);
            $error = 'Authentication failed. Reference the active platform error codes.';
        }
        page_header('Login');
        ?>
        <section class="login-grid">
          <div class="card">
            <p class="eyebrow">NETWORK ELEMENT MANAGEMENT</p>
            <h1>Operations sign-in</h1>
            <p class="muted">This appliance is operating under a restricted support licence.</p>
            <div class="alerts">
              <div><b>45009</b> Administrative credential state requires review.</div>
              <div><b>45010</b> Support licence validation has expired.</div>
            </div>
            <?php if ($error !== ''): ?><p class="error"><?= h($error) ?></p><?php endif; ?>
            <form method="post" autocomplete="off">
              <label>Username<input name="username" required></label>
              <label>Password<input type="password" name="password" required></label>
              <button type="submit">Sign in</button>
            </form>
          </div>
          <aside class="card dark">
            <h2>DakshinLink edge services</h2>
            <p>Inter-carrier routing, customer transit and network diagnostics.</p>
            <ul>
              <li>Read-only licence mode</li>
              <li>Configuration recovery window enabled</li>
              <li>Support documents available under <code>/doc/</code></li>
            </ul>
          </aside>
        </section>
        <?php page_footer(); ?>
