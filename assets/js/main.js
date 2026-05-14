document.addEventListener("mousemove", (e) => {
    const grid = document.querySelector(".grid-bg");
    if (!grid) return;

    const x = (e.clientX / window.innerWidth) * 20;
    const y = (e.clientY / window.innerHeight) * 20;

    grid.style.transform = `translate(${x}px, ${y}px)`;
});
