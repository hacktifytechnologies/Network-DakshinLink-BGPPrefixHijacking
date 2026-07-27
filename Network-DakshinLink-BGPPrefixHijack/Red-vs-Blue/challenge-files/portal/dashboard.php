<?php
        declare(strict_types=1);
        require_once __DIR__ . '/common.php';
        require_auth();
        audit_event('dashboard_view');
        page_header('Dashboard');
        ?>
        <section class="hero">
          <p class="eyebrow">CARRIER EDGE STATUS</p>
          <h1>DakshinLink routing operations</h1>
          <p>Configuration changes are available for authorised support activity. The recovery controller restores the approved router profile during challenge redeployment.</p>
        </section>
        <section class="metrics">
          <article class="card"><span>Routing stack</span><b>FRRouting</b><small>Operational</small></article>
          <article class="card"><span>Licence state</span><b>Read-only</b><small>Error 45010</small></article>
          <article class="card"><span>Support queue</span><b>6 tickets</b><small>1 requires routing review</small></article>
        </section>
        <section class="card">
          <h2>Operational notice</h2>
          <p>Peer policy changes must preserve connectivity between customer and service-provider autonomous systems.</p>
          <p><a class="button-link" href="/tickets.php">Review support tickets</a></p>
        </section>
        <?php page_footer(); ?>
