<?php
        declare(strict_types=1);
        require_once dirname(__DIR__) . '/common.php';
        audit_event('documentation_view');
        page_header('Support Documents');
        ?>
        <section class="hero compact"><p class="eyebrow">TECHNICAL ASSISTANCE CENTRE</p><h1>Documents</h1></section>
        <section class="card">
          <ul class="documents">
            <li><a href="/doc/error_codes.pdf">Platform error-code manual</a><small>PDF</small></li>
            <li><a href="/doc/diagram_for_tac.png">Inter-carrier topology for TAC</a><small>PNG</small></li>
          </ul>
        </section>
        <?php page_footer(); ?>
