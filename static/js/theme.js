// Runs before the page paints, so the chosen theme never flashes.
// Uses the saved choice, otherwise the operating system's setting.
(function () {
    var saved = null;
    try { saved = localStorage.getItem('netscan-theme'); } catch (e) { /* storage blocked */ }
    var prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
    document.documentElement.dataset.theme = saved || (prefersLight ? 'light' : 'dark');
})();
