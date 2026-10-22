// Site-wide behaviour: nav state, mobile menu, animated network background,
// scroll reveals, card spotlight and the home page terminal.
document.addEventListener("DOMContentLoaded", () => {
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // ---- Nav: highlight the current page (blog posts light up "Blog") ----
    const norm = (p) => (p.endsWith("/") ? p + "index.html" : p);
    const here = norm(window.location.pathname);
    const inBlog = here.includes("/blog/");
    const navLinks = [...document.querySelectorAll(".nav-links a")];
    let match = navLinks.find((link) => norm(link.pathname) === here);
    if (!match && inBlog) match = navLinks.find((link) => norm(link.pathname).endsWith("/blog/index.html"));
    if (!match && document.querySelector('.eyebrow-link[href="projects.html"]')) {
        match = navLinks.find((link) => norm(link.pathname).endsWith("/projects.html"));
    }
    if (match) match.classList.add("active");

    const yearEl = document.querySelector("[data-year]");
    if (yearEl) yearEl.textContent = new Date().getFullYear();

    // ---- Nav: solid on scroll, menu button on small screens ----
    const navbar = document.querySelector(".navbar");
    if (navbar) {
        const onScroll = () => navbar.classList.toggle("scrolled", window.scrollY > 12);
        onScroll();
        window.addEventListener("scroll", onScroll, { passive: true });

        const toggle = document.createElement("button");
        toggle.className = "nav-toggle";
        toggle.type = "button";
        toggle.setAttribute("aria-label", "Menu");
        toggle.setAttribute("aria-expanded", "false");
        toggle.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 7h16M4 12h16M4 17h16"/></svg>';
        toggle.addEventListener("click", () => {
            const open = navbar.classList.toggle("open");
            toggle.setAttribute("aria-expanded", String(open));
        });
        navbar.insertBefore(toggle, navbar.querySelector(".nav-links"));
    }

    // ---- Background: drifting network of nodes ----
    const bg = document.querySelector(".grid-bg");
    if (bg) {
        const canvas = document.createElement("canvas");
        bg.appendChild(canvas);
        const ctx = canvas.getContext("2d");
        const pointer = { x: -9999, y: -9999 };
        let nodes = [];
        let w = 0;
        let h = 0;
        let dpr = 1;

        const resize = () => {
            dpr = Math.min(window.devicePixelRatio || 1, 2);
            w = window.innerWidth;
            h = window.innerHeight;
            canvas.width = w * dpr;
            canvas.height = h * dpr;
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            const count = Math.round(Math.min(90, (w * h) / 18000));
            nodes = Array.from({ length: count }, () => ({
                x: Math.random() * w,
                y: Math.random() * h,
                vx: (Math.random() - 0.5) * 0.25,
                vy: (Math.random() - 0.5) * 0.25,
                r: Math.random() * 1.4 + 0.6,
                hue: Math.random() < 0.7 ? "62,207,178" : Math.random() < 0.5 ? "76,195,255" : "139,123,255",
            }));
        };

        const LINK = 140;
        const draw = () => {
            ctx.clearRect(0, 0, w, h);
            for (let i = 0; i < nodes.length; i++) {
                const a = nodes[i];
                for (let j = i + 1; j < nodes.length; j++) {
                    const b = nodes[j];
                    const dx = a.x - b.x;
                    const dy = a.y - b.y;
                    const d = Math.hypot(dx, dy);
                    if (d < LINK) {
                        ctx.strokeStyle = `rgba(${a.hue},${(1 - d / LINK) * 0.22})`;
                        ctx.lineWidth = 1;
                        ctx.beginPath();
                        ctx.moveTo(a.x, a.y);
                        ctx.lineTo(b.x, b.y);
                        ctx.stroke();
                    }
                }
                const pd = Math.hypot(a.x - pointer.x, a.y - pointer.y);
                if (pd < 180) {
                    ctx.strokeStyle = `rgba(76,195,255,${(1 - pd / 180) * 0.45})`;
                    ctx.beginPath();
                    ctx.moveTo(a.x, a.y);
                    ctx.lineTo(pointer.x, pointer.y);
                    ctx.stroke();
                }
                ctx.fillStyle = `rgba(${a.hue},0.9)`;
                ctx.beginPath();
                ctx.arc(a.x, a.y, a.r, 0, Math.PI * 2);
                ctx.fill();
            }
        };

        const step = () => {
            for (const n of nodes) {
                n.x += n.vx;
                n.y += n.vy;
                if (n.x < -20) n.x = w + 20;
                if (n.x > w + 20) n.x = -20;
                if (n.y < -20) n.y = h + 20;
                if (n.y > h + 20) n.y = -20;
            }
            draw();
            if (!document.hidden) requestAnimationFrame(step);
        };

        resize();
        window.addEventListener("resize", resize);
        if (reduceMotion) {
            draw();
        } else {
            window.addEventListener("pointermove", (e) => { pointer.x = e.clientX; pointer.y = e.clientY; }, { passive: true });
            document.addEventListener("pointerleave", () => { pointer.x = pointer.y = -9999; });
            document.addEventListener("visibilitychange", () => { if (!document.hidden) requestAnimationFrame(step); });
            requestAnimationFrame(step);
        }
    }

    // ---- Projects page: filter by category ----
    const filterBtns = document.querySelectorAll(".filter-btn");
    filterBtns.forEach((btn) => {
        btn.addEventListener("click", () => {
            const want = btn.dataset.filter;
            filterBtns.forEach((b) => {
                b.classList.toggle("active", b === btn);
                b.setAttribute("aria-pressed", String(b === btn));
            });
            document.querySelectorAll(".project-card[data-cat]").forEach((card) => {
                const show = want === "all" || card.dataset.cat.split(" ").includes(want);
                card.classList.toggle("filter-hidden", !show);
                if (show) card.classList.add("in");
            });
            // Hide a group's heading when none of its cards match
            document.querySelectorAll(".media-grid").forEach((grid) => {
                const empty = !grid.querySelector(".project-card:not(.filter-hidden)");
                grid.classList.toggle("filter-hidden", empty);
                const heading = grid.previousElementSibling;
                if (heading && heading.classList.contains("section-header")) heading.classList.toggle("filter-hidden", empty);
            });
        });
    });

    // ---- Card spotlight follows the pointer ----
    document.querySelectorAll(".project-card").forEach((card) => {
        card.addEventListener("pointermove", (e) => {
            const r = card.getBoundingClientRect();
            card.style.setProperty("--mx", `${e.clientX - r.left}px`);
            card.style.setProperty("--my", `${e.clientY - r.top}px`);
        });
    });

    // ---- Scroll reveals ----
    if (!reduceMotion && "IntersectionObserver" in window) {
        const targets = document.querySelectorAll(
            ".project-card, .post-link, .stat, .focus, .section-top, .project-image, .terminal-window"
        );
        const io = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    entry.target.classList.add("in");
                    io.unobserve(entry.target);
                }
            });
        }, { rootMargin: "0px 0px -8% 0px", threshold: 0.05 });

        targets.forEach((el) => {
            // Stagger siblings in grids so cards cascade in
            const parent = el.parentElement;
            if (parent && /project-grid|bento|focus-grid|stats/.test(parent.className)) {
                el.style.setProperty("--delay", `${Array.prototype.indexOf.call(parent.children, el) * 0.07}s`);
            }
            el.classList.add("reveal");
            io.observe(el);
        });
    }

    // ---- Home page terminal ----
    const term = document.getElementById("term-body");
    if (term) {
        const script = [
            ["p", "zombi3@lab:~$ ", "c", "whoami"],
            ["", "Aaron Moorcroft · penetration tester · dad of two\n"],
            ["p", "zombi3@lab:~$ ", "c", "ls ~/projects --featured"],
            ["b", "nightjarc2/   ", "", "C2 framework, lab use only\n"],
            ["b", "the-bounty/   ", "", "contract hacker sim for iOS\n"],
            ["b", "cyberos/      ", "", "x86 OS in 17k lines of NASM\n"],
            ["b", "pentest-agent/", "", "LLM-driven recon loop\n"],
            ["b", "ember/        ", "", "personal Debian build\n"],
            ["p", "zombi3@lab:~$ ", "c", "status"],
            ["ok", "● ", "", "building, breaking, learning\n"],
            ["p", "zombi3@lab:~$ ", "c", ""],
        ];

        const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
        const render = (parts) => parts.map(([cls, text]) => (cls ? `<span class="${cls}">${esc(text)}</span>` : esc(text))).join("");

        // Flatten into [class, text] segments; commands type out, output appears at once
        const lines = script.map((l) => {
            const segs = [];
            for (let i = 0; i < l.length; i += 2) segs.push([l[i], l[i + 1]]);
            const isCmd = l[0] === "p";
            if (isCmd && l[3] !== "") segs.push(["", "\n"]);
            return { segs, isCmd };
        });

        if (reduceMotion) {
            term.innerHTML = lines.map((l) => render(l.segs)).join("") + '<span class="caret"></span>';
        } else {
            const done = [];
            let li = 0;
            const next = () => {
                if (li >= lines.length) {
                    term.innerHTML = render(done) + '<span class="caret"></span>';
                    return;
                }
                const line = lines[li++];
                if (!line.isCmd) {
                    done.push(...line.segs);
                    term.innerHTML = render(done) + '<span class="caret"></span>';
                    setTimeout(next, 90);
                    return;
                }
                const [prompt, cmd] = line.segs;
                done.push(prompt);
                const typed = ["c", ""];
                done.push(typed);
                let ci = 0;
                const type = () => {
                    if (ci < cmd[1].length) {
                        typed[1] += cmd[1][ci++];
                        term.innerHTML = render(done) + '<span class="caret"></span>';
                        setTimeout(type, 38 + Math.random() * 50);
                    } else {
                        done.push(...line.segs.slice(2));
                        setTimeout(next, 380);
                    }
                };
                setTimeout(type, 300);
            };
            next();
        }
    }
});
