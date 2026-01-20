<?php
$title = 'Page Not Found';
?>
<?php ob_start(); ?>

<div class="error-page">
    <h1>404</h1>
    <p>Page not found</p>
    <a href="/" class="btn btn-primary">Go to Home</a>
</div>

<?php $content = ob_get_clean(); ?>
<?php include __DIR__ . '/../layout.php'; ?>
