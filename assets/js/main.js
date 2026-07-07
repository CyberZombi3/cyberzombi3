// Highlight the current page in the nav
document.addEventListener("DOMContentLoaded", () => {
    const links = document.querySelectorAll(".nav-links a");
    const current = window.location.pathname.split("/").pop() || "index.html";

    links.forEach((link) => {
        const href = link.getAttribute("href");
        if (href && href.endsWith(current) && current !== "") {
            link.classList.add("active");
        }
    });

    const yearEl = document.querySelector("[data-year]");
    if (yearEl) {
        yearEl.textContent = new Date().getFullYear();
    }
});
