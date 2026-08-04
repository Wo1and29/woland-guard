function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
const {
  useState,
  useEffect,
  useRef
} = React;
const {
  motion,
  MotionConfig
} = window.Motion;
const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/* ---------------------------------------------------------------- icons */

function ArrowUpRight({
  className = "h-4 w-4"
}) {
  return /*#__PURE__*/React.createElement("svg", {
    className: className,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round",
    "aria-hidden": "true"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M7 17L17 7"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M7 7h10v10"
  }));
}
function MaterialIcon({
  d
}) {
  return /*#__PURE__*/React.createElement("svg", {
    className: "h-6 w-6 text-white",
    viewBox: "0 0 24 24",
    fill: "currentColor",
    "aria-hidden": "true"
  }, /*#__PURE__*/React.createElement("path", {
    d: d
  }));
}
const ICON = {
  shield: "M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4Zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8Z",
  history: "M13 3a9 9 0 0 0-9 9H1l3.89 3.89.07.14L9 12H6a7 7 0 1 1 2.05 4.95l-1.42 1.42A9 9 0 1 0 13 3Zm-1 5v5l4.28 2.54.72-1.21-3.5-2.08V8H12Z",
  key: "M12.65 10A6 6 0 0 0 7 6a6 6 0 0 0 0 12 6 6 0 0 0 5.65-4H17v4h4v-4h2v-4H12.65ZM7 14a2 2 0 1 1 0-4 2 2 0 0 1 0 4Z",
  bell: "M12 22c1.1 0 2-.9 2-2h-4a2 2 0 0 0 2 2Zm6-6v-5c0-3.07-1.64-5.64-4.5-6.32V4a1.5 1.5 0 0 0-3 0v.68C7.63 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2Z",
  storage: "M2 20h20v-4H2v4Zm2-3h2v2H4v-2ZM2 4v4h20V4H2Zm4 3H4V5h2v2ZM2 14h20v-4H2v4Zm2-3h2v2H4v-2Z"
};

/* ------------------------------------------------------------ i18n dict */

const DICT = {
  "nav.project": {
    ru: "Проект",
    en: "Project"
  },
  "nav.services": {
    ru: "Услуги",
    en: "Services"
  },
  "nav.pricing": {
    ru: "Тарифы",
    en: "Pricing"
  },
  "nav.cta": {
    ru: "Связаться",
    en: "Get in touch"
  },
  "nav.toTop": {
    ru: "Наверх",
    en: "Back to top"
  },
  "hero.badgeChip": {
    ru: "Open source",
    en: "Open source"
  },
  "hero.badge": {
    ru: "Woland Guard — движок детекции по MITRE ATT&CK, AGPL-3.0",
    en: "Woland Guard — a MITRE ATT&CK detection engine, AGPL-3.0"
  },
  "hero.h1": {
    ru: "Вижу вторжение раньше, чем оно станет инцидентом",
    en: "See the intrusion before it becomes an incident"
  },
  "hero.lede": {
    ru: "Проектирую и внедряю системы обнаружения угроз и аудита для Linux-серверов: правила детекции по MITRE ATT&CK, ролевой доступ, полный журнал решений и Telegram-оповещения с разбором инцидента прямо в чате.",
    en: "I design and build threat detection and audit systems for Linux servers: detection rules mapped to MITRE ATT&CK, role-based access, a full decision log, and Telegram alerts with incident triage right in the chat."
  },
  "hero.ctaPrimary": {
    ru: "Обсудить задачу",
    en: "Discuss a project"
  },
  "hero.ctaSecondary": {
    ru: "Код на GitHub",
    en: "Code on GitHub"
  },
  "hero.feedHead": {
    ru: "уведомление · пример",
    en: "sample notification"
  },
  "hero.feedJustNow": {
    ru: "только что",
    en: "just now"
  },
  "hero.feedCaption": {
    ru: "Так выглядит уведомление оператора — пример, не боевые данные.",
    en: "This is what an operator's notification looks like — a sample, not live data."
  },
  "hero.stackNote": {
    ru: "Собрано на проверенном стеке, без магии",
    en: "Built on a proven stack, no magic"
  },
  "hero.watermark": {
    ru: "Session log · uptime 24/7",
    en: "Session log · uptime 24/7"
  },
  "svc.kicker": {
    ru: "// Услуги",
    en: "// Services"
  },
  "svc.h2a": {
    ru: "Защита,",
    en: "Defence"
  },
  "svc.h2b": {
    ru: "которая объясняет себя",
    en: "that explains itself"
  },
  "svc.card1Title": {
    ru: "Мониторинг вторжений",
    en: "Intrusion monitoring"
  },
  "svc.card1Desc": {
    ru: "Детекция подозрительной активности — перебор паролей, вход под root, изменение привилегированных групп — с привязкой к тактикам MITRE ATT&CK.",
    en: "Detection for suspicious activity — password guessing, root logins, privileged group changes — mapped to MITRE ATT&CK tactics."
  },
  "svc.card2Title": {
    ru: "Аудит и трассируемость",
    en: "Audit and traceability"
  },
  "svc.card2Desc": {
    ru: "Журнал, который фиксирует каждое решение системы и оператора и выдерживает разбор инцидента постфактум.",
    en: "A log that records every decision the system and the operator make, and holds up to a post-incident review."
  },
  "svc.card3Title": {
    ru: "Ролевой доступ",
    en: "Role-based access"
  },
  "svc.card3Desc": {
    ru: "Права аналитика и администратора разграничены на уровне каждого действия, а не только страницы интерфейса.",
    en: "Analyst and administrator permissions separated at the level of each action, not just each page."
  },
  "svc.card4Title": {
    ru: "Оповещения и реагирование",
    en: "Alerting and response"
  },
  "svc.card4Desc": {
    ru: "Telegram-бот с кнопками: принять инцидент, закрыть, подготовить блокировку адреса — с одобрением вторым оператором.",
    en: "A Telegram bot with buttons: take an incident, close it, prepare an IP block — with a second operator's approval."
  },
  "svc.card5Title": {
    ru: "Архитектура и ревью",
    en: "Architecture and review"
  },
  "svc.card5Desc": {
    ru: "Бэкенд на FastAPI, SQLAlchemy и PostgreSQL — или разбор существующей системы мониторинга и прямой ответ, что стоит переделать.",
    en: "Backends on FastAPI, SQLAlchemy and PostgreSQL — or a review of an existing monitoring system and a plain answer on what needs rebuilding."
  },
  "prj.kicker": {
    ru: "// Флагманский проект",
    en: "// Flagship project"
  },
  "prj.lede": {
    ru: "Открытая система мониторинга безопасности Linux-серверов, спроектированная и написанная с нуля: движок детекции по MITRE ATT&CK, ролевой доступ, полный audit trail и интерактивный Telegram-бот. Работающая система, а не витрина — с тестами и ревью на каждом шаге.",
    en: "An open-source Linux server security monitoring system, designed and built from scratch: a detection engine mapped to MITRE ATT&CK, role-based access, a full audit trail, and an interactive Telegram bot. A working system, not a showcase — tested and reviewed at every step."
  },
  "prj.stat1": {
    ru: "строк production-кода",
    en: "lines of production code"
  },
  "prj.stat2": {
    ru: "строк тестов",
    en: "lines of tests"
  },
  "prj.stat3": {
    ru: "архитектурных решений в ADR",
    en: "architecture decisions in ADRs"
  },
  "prj.stat4": {
    ru: "открытая лицензия",
    en: "open license"
  },
  "prj.shot1Alt": {
    ru: "Обзор Woland Guard: серверы, активные инциденты и очередь уведомлений",
    en: "Woland Guard overview: servers, active incidents and the notification queue"
  },
  "prj.shot1Cap": {
    ru: "Обзор: серверы, активные инциденты, очередь уведомлений",
    en: "Overview: servers, active incidents, notification queue"
  },
  "prj.shot2Alt": {
    ru: "Список инцидентов Woland Guard с фильтрами, severity и счётчиком evidence",
    en: "Woland Guard incident list with filters, severity and evidence counts"
  },
  "prj.shot2Cap": {
    ru: "Инциденты: фильтры, severity, привязка к версии правила, evidence",
    en: "Incidents: filters, severity, rule version binding, evidence"
  },
  "prj.proof": {
    ru: "Смотреть исходный код",
    en: "View the source"
  },
  "prc.kicker": {
    ru: "// Тарифы",
    en: "// Pricing"
  },
  "prc.h2a": {
    ru: "Прозрачно",
    en: "Transparent"
  },
  "prc.h2b": {
    ru: "как audit trail",
    en: "like an audit trail"
  },
  "prc.t1Title": {
    ru: "Быстрый старт",
    en: "Quick start"
  },
  "prc.t1Price": {
    ru: "от 15 000 ₽",
    en: "from ₽15,000"
  },
  "prc.t1Desc": {
    ru: "Разворачиваю Woland Guard под вашу инфраструктуру: Docker Compose, базовый набор правил детекции, Telegram-оповещения.",
    en: "I deploy Woland Guard on your infrastructure: Docker Compose, a baseline set of detection rules, Telegram alerts."
  },
  "prc.t1a": {
    ru: "До 3 серверов",
    en: "Up to 3 servers"
  },
  "prc.t1b": {
    ru: "Готовые правила детекции",
    en: "Ready-made detection rules"
  },
  "prc.t1c": {
    ru: "Telegram-оповещения",
    en: "Telegram alerts"
  },
  "prc.t2Badge": {
    ru: "Чаще всего выбирают",
    en: "Most popular"
  },
  "prc.t2Title": {
    ru: "Под задачу",
    en: "Custom fit"
  },
  "prc.t2Price": {
    ru: "от 40 000 ₽",
    en: "from ₽40,000"
  },
  "prc.t2Desc": {
    ru: "Кастомные правила детекции под ваши риски, ролевой доступ под структуру команды, полный audit trail.",
    en: "Custom detection rules for your risks, role-based access matching your team's structure, a full audit trail."
  },
  "prc.t2a": {
    ru: "До 10 серверов",
    en: "Up to 10 servers"
  },
  "prc.t2b": {
    ru: "Правила под ваши риски",
    en: "Rules for your risks"
  },
  "prc.t2c": {
    ru: "Ролевой доступ и аудит",
    en: "Role-based access and audit"
  },
  "prc.t2d": {
    ru: "Интерактивный Telegram-бот",
    en: "Interactive Telegram bot"
  },
  "prc.t3Title": {
    ru: "Индивидуальная разработка",
    en: "Custom build"
  },
  "prc.t3Price": {
    ru: "по ТЗ",
    en: "quote on request"
  },
  "prc.t3Desc": {
    ru: "Проектирую и разрабатываю систему безопасности с нуля: собственная архитектура, интеграции, перенос существующих логов.",
    en: "I design and build a security system from scratch: its own architecture, integrations, migrating existing logs."
  },
  "prc.t3a": {
    ru: "Архитектура под требования",
    en: "Architecture built to your requirements"
  },
  "prc.t3b": {
    ru: "Интеграция с вашими системами",
    en: "Integration with your systems"
  },
  "prc.t3c": {
    ru: "Консультации по ходу проекта",
    en: "Consulting throughout the project"
  },
  "prc.note": {
    ru: "Итоговая стоимость зависит от инфраструктуры и объёма работ — обсуждаем до начала.",
    en: "Final cost depends on your infrastructure and scope — we discuss it before starting."
  },
  "ct.kicker": {
    ru: "// Связь",
    en: "// Contact"
  },
  "ct.h2a": {
    ru: "Обсудим вашу",
    en: "Let's talk about"
  },
  "ct.h2b": {
    ru: "инфраструктуру",
    en: "your infrastructure"
  },
  "ct.lede": {
    ru: "Расскажите, что нужно защитить и от чего — отвечу и предложу вариант решения.",
    en: "Tell me what needs protecting and from what — I'll reply with a proposed approach."
  },
  "ft.license": {
    ru: "Woland Guard распространяется по лицензии",
    en: "Woland Guard is licensed under"
  }
};
function useT() {
  const [lang, setLang] = useState(() => {
    try {
      const saved = localStorage.getItem("wg-lang");
      if (saved === "ru" || saved === "en") return saved;
    } catch (e) {}
    return "ru";
  });
  useEffect(() => {
    document.documentElement.setAttribute("lang", lang);
    document.title = lang === "ru" ? "Dr. Woland — мониторинг и аудит безопасности Linux-серверов" : "Dr. Woland — Linux server security monitoring and audit";
    try {
      localStorage.setItem("wg-lang", lang);
    } catch (e) {}
  }, [lang]);
  const t = key => DICT[key] ? DICT[key][lang] : key;
  return {
    lang,
    setLang,
    t
  };
}

/* --------------------------------------------------- SignalField canvas
   The project's own background: a server mesh with a sweeping scan line and
   a few nodes flaring red. Replaces the template's stock video. */

function SignalField({
  density = 74,
  scanSpeed = 0.55,
  alertRate = 0.05,
  opacity = 0.7
}) {
  const canvasRef = useRef(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !canvas.getContext) return;
    const ctx = canvas.getContext("2d");
    const reduced = reducedMotion();
    let W = 0,
      H = 0,
      DPR = 1,
      nodes = [],
      t = 0,
      scanY = 0,
      raf = null;
    const buildNodes = () => {
      nodes = [];
      const cols = Math.max(6, Math.round(W / density));
      const rows = Math.max(4, Math.round(H / density));
      for (let i = 0; i < cols; i++) {
        for (let j = 0; j < rows; j++) {
          nodes.push({
            x: (i + 0.5) * (W / cols) + (Math.random() - 0.5) * 20,
            y: (j + 0.5) * (H / rows) + (Math.random() - 0.5) * 20,
            phase: Math.random() * Math.PI * 2,
            alert: Math.random() < alertRate
          });
        }
      }
    };
    const resize = () => {
      const rect = canvas.parentElement.getBoundingClientRect();
      DPR = Math.min(window.devicePixelRatio || 1, 2);
      W = rect.width;
      H = rect.height;
      canvas.width = W * DPR;
      canvas.height = H * DPR;
      canvas.style.width = W + "px";
      canvas.style.height = H + "px";
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      buildNodes();
    };
    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      ctx.lineWidth = 1;
      for (let i = 0; i < nodes.length; i++) {
        for (let k = i + 1; k < nodes.length; k++) {
          const a = nodes[i],
            b = nodes[k];
          const dx = a.x - b.x,
            dy = a.y - b.y;
          const d = Math.sqrt(dx * dx + dy * dy);
          if (d < 95) {
            ctx.globalAlpha = (1 - d / 95) * 0.5;
            ctx.strokeStyle = "rgba(127,194,224,0.16)";
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }
      ctx.globalAlpha = 1;
      for (const node of nodes) {
        const pulse = 0.5 + 0.5 * Math.sin(t * 0.02 + node.phase);
        const r = node.alert ? 2.1 + pulse * 1.5 : 1.3;
        ctx.beginPath();
        ctx.fillStyle = node.alert ? "rgba(226,105,90," + (0.4 + pulse * 0.5) + ")" : "rgba(127,194,224," + (0.28 + pulse * 0.28) + ")";
        ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.fillStyle = "rgba(127,194,224,0.05)";
      ctx.fillRect(0, scanY - 46, W, 92);
      ctx.strokeStyle = "rgba(127,194,224,0.3)";
      ctx.beginPath();
      ctx.moveTo(0, scanY);
      ctx.lineTo(W, scanY);
      ctx.stroke();
    };
    const loop = () => {
      t++;
      scanY += scanSpeed;
      if (scanY > H + 46) scanY = -46;
      draw();
      raf = requestAnimationFrame(loop);
    };
    window.addEventListener("resize", resize);
    resize();
    scanY = H * 0.3;
    if (reduced) draw();else raf = requestAnimationFrame(loop);
    return () => {
      window.removeEventListener("resize", resize);
      if (raf) cancelAnimationFrame(raf);
    };
    // ponytail: O(n²) link pass, fine at this node count; spatial hash if density ever drops below ~50
  }, [density, scanSpeed, alertRate]);
  return /*#__PURE__*/React.createElement("canvas", {
    ref: canvasRef,
    "aria-hidden": "true",
    className: "absolute inset-0 w-full h-full block z-0",
    style: {
      opacity
    }
  });
}

/* ---------------------------------------------------------- BlurText */

function BlurText({
  text,
  className
}) {
  const ref = useRef(null);
  // Without IntersectionObserver nothing would ever flip `animate` on and the
  // headline would stay at its initial opacity: 0 forever.
  const [inView, setInView] = useState(() => !("IntersectionObserver" in window));
  useEffect(() => {
    const el = ref.current;
    if (!el || !("IntersectionObserver" in window)) return;
    const io = new IntersectionObserver(entries => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          setInView(true);
          io.unobserve(el);
        }
      });
    }, {
      threshold: 0.1
    });
    io.observe(el);
    return () => io.disconnect();
  }, []);
  const words = text.split(" ");
  // h1: this is the page's only headline-level hero text and the sole
  // caller (the hero on #top); the whole page otherwise has zero <h1>s.
  return /*#__PURE__*/React.createElement("h1", {
    ref: ref,
    className: className,
    style: {
      display: "flex",
      flexWrap: "wrap",
      justifyContent: "center",
      rowGap: "0.1em"
    }
  }, words.map((word, i) => /*#__PURE__*/React.createElement(motion.span, {
    key: `${word}-${i}`,
    initial: {
      filter: "blur(10px)",
      opacity: 0,
      y: 50
    },
    animate: inView ? {
      filter: ["blur(10px)", "blur(5px)", "blur(0px)"],
      opacity: [0, 0.5, 1],
      y: [50, -5, 0]
    } : {},
    transition: {
      duration: 0.7,
      times: [0, 0.5, 1],
      ease: "easeOut",
      delay: i * 100 / 1000
    },
    style: {
      display: "inline-block",
      marginRight: "0.28em"
    }
  }, word)));
}

/* ------------------------------------------------------------ shared */

const rise = delay => ({
  initial: {
    filter: "blur(10px)",
    opacity: 0,
    y: 20
  },
  whileInView: {
    filter: "blur(0px)",
    opacity: 1,
    y: 0
  },
  viewport: {
    once: true,
    amount: 0.2
  },
  transition: {
    duration: 0.6,
    ease: "easeOut",
    delay
  }
});
const riseNow = delay => ({
  initial: {
    filter: "blur(10px)",
    opacity: 0,
    y: 20
  },
  animate: {
    filter: "blur(0px)",
    opacity: 1,
    y: 0
  },
  transition: {
    duration: 0.6,
    ease: "easeOut",
    delay
  }
});
function Kicker({
  children
}) {
  return /*#__PURE__*/React.createElement("p", {
    className: "text-sm font-mono text-signal/90 mb-6 tracking-[0.06em]"
  }, children);
}
function Display({
  children,
  className = ""
}) {
  return /*#__PURE__*/React.createElement("h2", {
    className: `font-body font-semibold not-italic text-white text-6xl md:text-7xl lg:text-[6rem] leading-[0.9] tracking-[-3px] ${className}`
  }, children);
}

/* ------------------------------------------------------------ navbar */

function Navbar({
  lang,
  setLang,
  t
}) {
  // No "Контакты" link: the CTA button next to it already goes to #contact.
  const links = [["#project", t("nav.project")], ["#services", t("nav.services")], ["#pricing", t("nav.pricing")]];
  const toggle = () => setLang(lang === "ru" ? "en" : "ru");
  // The href stays as a no-JS fallback; this just makes the jump smooth and
  // keeps the URL clean of a trailing #top.
  const toTop = event => {
    event.preventDefault();
    window.scrollTo({
      top: 0,
      behavior: reducedMotion() ? "auto" : "smooth"
    });
  };
  return /*#__PURE__*/React.createElement("div", {
    className: "fixed top-4 left-0 right-0 z-50 px-8 lg:px-16"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-between gap-4"
  }, /*#__PURE__*/React.createElement("a", {
    href: "#top",
    onClick: toTop,
    title: t("nav.toTop"),
    "aria-label": t("nav.toTop"),
    className: "liquid-glass liquid-glass-signal h-12 w-12 shrink-0 rounded-full flex items-center justify-center"
  }, /*#__PURE__*/React.createElement("span", {
    className: "font-body font-semibold not-italic text-white text-2xl leading-none"
  }, "w")), /*#__PURE__*/React.createElement("div", {
    className: "hidden md:flex items-center"
  }, /*#__PURE__*/React.createElement("div", {
    className: "liquid-glass rounded-full px-1.5 py-1.5 flex items-center"
  }, links.map(([href, label]) => /*#__PURE__*/React.createElement("a", {
    key: href,
    href: href,
    className: "px-3 py-2 text-sm font-medium text-white/90 font-body hover:text-white"
  }, label)), /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: toggle,
    "aria-label": "Switch language / \u041F\u0435\u0440\u0435\u043A\u043B\u044E\u0447\u0438\u0442\u044C \u044F\u0437\u044B\u043A",
    className: "mx-1 px-3 py-2 text-sm font-medium font-mono text-white/60 hover:text-signal"
  }, lang === "ru" ? "EN" : "RU"), /*#__PURE__*/React.createElement("a", {
    href: "#contact",
    className: "bg-white text-black rounded-full px-4 py-2 text-sm font-medium font-body inline-flex items-center gap-1.5 whitespace-nowrap"
  }, t("nav.cta"), /*#__PURE__*/React.createElement(ArrowUpRight, {
    className: "h-4 w-4"
  })))), /*#__PURE__*/React.createElement("div", {
    className: "md:hidden flex items-center gap-2"
  }, /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: toggle,
    "aria-label": "Switch language / \u041F\u0435\u0440\u0435\u043A\u043B\u044E\u0447\u0438\u0442\u044C \u044F\u0437\u044B\u043A",
    className: "liquid-glass rounded-full px-4 h-12 text-sm font-medium font-mono text-white"
  }, lang === "ru" ? "EN" : "RU"), /*#__PURE__*/React.createElement("a", {
    href: "#contact",
    className: "bg-white text-black rounded-full px-4 h-12 text-sm font-medium font-body inline-flex items-center whitespace-nowrap"
  }, t("nav.cta"))), /*#__PURE__*/React.createElement("div", {
    className: "hidden md:block h-12 w-12 shrink-0",
    "aria-hidden": "true"
  })));
}

/* ------------------------------------------------------- incident feed */

const SEV_STYLE = {
  critical: "text-critical bg-critical/15",
  warning: "text-warning bg-warning/15",
  info: "text-info bg-info/15"
};
const FEED = [["critical", "ssh_root_login_success", "T1078 · Valid Accounts", "db-primary-01", "02:14:07"], ["warning", "ssh_bruteforce_by_ip", "T1110 · Brute Force", "bastion-eu-west-1", "01:52:33"], ["info", "user_account_created", "T1136 · Create Account", "api-gateway-02", "00:47:11"]];
function IncidentFeed({
  t
}) {
  const [incoming, setIncoming] = useState(reducedMotion());
  useEffect(() => {
    if (reducedMotion()) return;
    const id = setTimeout(() => setIncoming(true), 1900);
    return () => clearTimeout(id);
  }, []);
  const Row = ({
    sev,
    rule,
    tactic,
    host,
    time,
    dim
  }) => /*#__PURE__*/React.createElement("div", {
    className: `flex items-start gap-3 px-4 py-3.5 border-t border-white/10 transition-all duration-500 ${dim ? "opacity-0 translate-y-2" : "opacity-100 translate-y-0"}`
  }, /*#__PURE__*/React.createElement("span", {
    className: `shrink-0 rounded-[5px] px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.05em] ${SEV_STYLE[sev]}`
  }, sev), /*#__PURE__*/React.createElement("span", {
    className: "min-w-0 flex-1"
  }, /*#__PURE__*/React.createElement("span", {
    className: "block font-mono text-[13px] text-white break-all"
  }, rule), /*#__PURE__*/React.createElement("span", {
    className: "block font-mono text-[11px] text-white/45 mt-0.5"
  }, tactic, " \xB7 ", host)), /*#__PURE__*/React.createElement("span", {
    className: "shrink-0 font-mono text-[11px] text-white/45 whitespace-nowrap"
  }, time));
  return /*#__PURE__*/React.createElement("div", {
    className: "liquid-glass liquid-glass-signal rounded-[1.25rem] w-full max-w-xl text-left overflow-hidden"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-between px-4 py-3 font-mono text-[10px] uppercase tracking-[0.1em] text-white/45"
  }, /*#__PURE__*/React.createElement("span", {
    className: "flex items-center gap-2"
  }, /*#__PURE__*/React.createElement("span", {
    className: "h-1.5 w-1.5 rounded-full bg-signal inline-block"
  }), t("hero.feedHead")), /*#__PURE__*/React.createElement("span", null, "#WG-INC")), FEED.map(([sev, rule, tactic, host, time]) => /*#__PURE__*/React.createElement(Row, {
    key: rule,
    sev: sev,
    rule: rule,
    tactic: tactic,
    host: host,
    time: time
  })), /*#__PURE__*/React.createElement(Row, {
    sev: "warning",
    rule: "privileged_group_membership_changed",
    tactic: "T1098 \xB7 Account Manipulation",
    host: "web-frontend-01",
    time: t("hero.feedJustNow"),
    dim: !incoming
  }), /*#__PURE__*/React.createElement("div", {
    className: "px-4 py-3 border-t border-white/10 text-[11px] text-white/40 font-body font-light"
  }, t("hero.feedCaption")));
}

/* -------------------------------------------------------------- hero */

function Hero({
  t
}) {
  const stack = ["FastAPI", "PostgreSQL", "SQLAlchemy", "Telegram", "Docker"];
  return /*#__PURE__*/React.createElement("section", {
    id: "top",
    className: "relative min-h-screen w-full overflow-hidden bg-black"
  }, /*#__PURE__*/React.createElement(SignalField, {
    density: 74,
    opacity: 0.7
  }), /*#__PURE__*/React.createElement("div", {
    className: "pointer-events-none absolute inset-0 z-[1]",
    style: {
      background: "radial-gradient(ellipse 60% 55% at 50% 12%, rgba(127,194,224,0.16), transparent 62%)"
    },
    "aria-hidden": "true"
  }), /*#__PURE__*/React.createElement("div", {
    className: "relative z-10 flex min-h-screen flex-col"
  }, /*#__PURE__*/React.createElement("div", {
    className: "absolute top-[1.6rem] right-8 lg:right-16 font-mono text-[10px] uppercase tracking-[0.18em] text-white/25 hidden lg:block"
  }, t("hero.watermark")), /*#__PURE__*/React.createElement("div", {
    className: "flex-1 flex flex-col items-center justify-center text-center pt-32 pb-12 px-4"
  }, /*#__PURE__*/React.createElement(motion.div, riseNow(0.4), /*#__PURE__*/React.createElement("div", {
    className: "liquid-glass rounded-full inline-flex items-center gap-3"
  }, /*#__PURE__*/React.createElement("span", {
    className: "bg-white text-black rounded-full px-3 py-1 text-xs font-semibold font-body"
  }, t("hero.badgeChip")), /*#__PURE__*/React.createElement("span", {
    className: "text-sm text-white/90 pr-3 font-body"
  }, t("hero.badge")))), /*#__PURE__*/React.createElement(BlurText, {
    key: t("hero.h1"),
    text: t("hero.h1"),
    className: "mt-6 text-5xl md:text-7xl lg:text-[5.5rem] font-body font-semibold not-italic text-white leading-[0.8] max-w-3xl justify-center tracking-[-4px]"
  }), /*#__PURE__*/React.createElement(motion.p, _extends({}, riseNow(0.8), {
    className: "mt-5 text-sm md:text-base text-white/85 max-w-2xl font-body font-light leading-snug"
  }), t("hero.lede")), /*#__PURE__*/React.createElement(motion.div, _extends({}, riseNow(1.1), {
    className: "flex items-center gap-6 mt-7"
  }), /*#__PURE__*/React.createElement("a", {
    href: "#contact",
    className: "liquid-glass-strong rounded-full px-5 py-2.5 text-sm font-medium text-white font-body inline-flex items-center gap-2"
  }, t("hero.ctaPrimary"), /*#__PURE__*/React.createElement(ArrowUpRight, {
    className: "h-5 w-5"
  })), /*#__PURE__*/React.createElement("a", {
    href: "https://github.com/Wo1and29/woland-guard",
    target: "_blank",
    rel: "noopener",
    className: "text-sm font-medium text-white font-body inline-flex items-center gap-2 hover:text-signal"
  }, t("hero.ctaSecondary"), /*#__PURE__*/React.createElement(ArrowUpRight, {
    className: "h-4 w-4"
  }))), /*#__PURE__*/React.createElement(motion.div, _extends({}, riseNow(1.3), {
    className: "mt-10 w-full flex justify-center"
  }), /*#__PURE__*/React.createElement(IncidentFeed, {
    t: t
  }))), /*#__PURE__*/React.createElement(motion.div, _extends({}, riseNow(1.5), {
    className: "flex flex-col items-center gap-4 pb-8 px-4"
  }), /*#__PURE__*/React.createElement("div", {
    className: "liquid-glass rounded-full px-3.5 py-1 text-xs font-medium text-white font-body text-center"
  }, t("hero.stackNote")), /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap justify-center gap-8 md:gap-14"
  }, stack.map(name => /*#__PURE__*/React.createElement("span", {
    key: name,
    className: "font-body font-semibold not-italic text-white/90 text-2xl md:text-3xl tracking-tight"
  }, name))))));
}

/* ---------------------------------------------------------- services */

function ServiceCard({
  iconPath,
  tags,
  title,
  body
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: "liquid-glass rounded-[1.25rem] p-6 min-h-[360px] h-full flex flex-col"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-start justify-between gap-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "liquid-glass liquid-glass-signal h-11 w-11 shrink-0 rounded-[0.75rem] flex items-center justify-center"
  }, /*#__PURE__*/React.createElement(MaterialIcon, {
    d: iconPath
  })), /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap justify-end gap-1.5 max-w-[70%]"
  }, tags.map(tag => /*#__PURE__*/React.createElement("span", {
    key: tag,
    className: "liquid-glass rounded-full px-3 py-1 text-[11px] text-white/90 font-mono whitespace-nowrap"
  }, tag)))), /*#__PURE__*/React.createElement("div", {
    className: "flex-1"
  }), /*#__PURE__*/React.createElement("div", {
    className: "mt-6"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-body font-semibold not-italic text-white text-3xl md:text-4xl tracking-[-1px] leading-none"
  }, title), /*#__PURE__*/React.createElement("p", {
    className: "mt-3 text-sm text-white/85 font-body font-light leading-snug max-w-[34ch]"
  }, body)));
}
function Services({
  t
}) {
  const cards = [{
    iconPath: ICON.shield,
    tags: ["TA0006", "Credential Access", "sshd", "auditd"],
    title: t("svc.card1Title"),
    body: t("svc.card1Desc")
  }, {
    iconPath: ICON.history,
    tags: ["TA0005", "Defense Evasion", "Audit trail"],
    title: t("svc.card2Title"),
    body: t("svc.card2Desc")
  }, {
    iconPath: ICON.key,
    tags: ["TA0004", "Privilege Escalation", "RBAC"],
    title: t("svc.card3Title"),
    body: t("svc.card3Desc")
  }, {
    iconPath: ICON.bell,
    tags: ["Telegram Bot API", "Four-eyes", "Inline keyboard"],
    title: t("svc.card4Title"),
    body: t("svc.card4Desc")
  }, {
    iconPath: ICON.storage,
    tags: ["FastAPI", "SQLAlchemy", "PostgreSQL", "Alembic"],
    title: t("svc.card5Title"),
    body: t("svc.card5Desc")
  }];
  return /*#__PURE__*/React.createElement("section", {
    id: "services",
    className: "relative min-h-screen w-full overflow-hidden bg-black"
  }, /*#__PURE__*/React.createElement(SignalField, {
    density: 96,
    scanSpeed: 0.35,
    alertRate: 0.03,
    opacity: 0.5
  }), /*#__PURE__*/React.createElement("div", {
    className: "pointer-events-none absolute inset-0 z-[1]",
    style: {
      background: "radial-gradient(ellipse 70% 60% at 15% 0%, rgba(127,194,224,0.12), transparent 60%)"
    },
    "aria-hidden": "true"
  }), /*#__PURE__*/React.createElement("div", {
    className: "relative z-10 px-8 md:px-16 lg:px-20 pt-28 pb-16 flex flex-col min-h-screen"
  }, /*#__PURE__*/React.createElement(motion.div, _extends({}, rise(0), {
    className: "mb-auto"
  }), /*#__PURE__*/React.createElement(Kicker, null, t("svc.kicker")), /*#__PURE__*/React.createElement(Display, null, t("svc.h2a"), /*#__PURE__*/React.createElement("br", null), t("svc.h2b"))), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mt-16"
  }, cards.map((card, i) => /*#__PURE__*/React.createElement(motion.div, _extends({
    key: card.title
  }, rise(i * 0.07)), /*#__PURE__*/React.createElement(ServiceCard, card))))));
}

/* ----------------------------------------------------------- project */

function Project({
  lang,
  t
}) {
  const stats = [["23 500+", t("prj.stat1")], ["24 500+", t("prj.stat2")], ["16", t("prj.stat3")], ["AGPL-3.0", t("prj.stat4")]];
  // The dashboard itself is bilingual, so show the operator the build in the
  // language they are reading the page in.
  const suffix = lang === "en" ? "_en" : "";
  const shots = [[`shot1${suffix}.png`, t("prj.shot1Alt"), t("prj.shot1Cap")], [`shot2${suffix}.png`, t("prj.shot2Alt"), t("prj.shot2Cap")]];
  return /*#__PURE__*/React.createElement("section", {
    id: "project",
    className: "relative w-full bg-black overflow-hidden"
  }, /*#__PURE__*/React.createElement("div", {
    className: "pointer-events-none absolute inset-0 z-0",
    style: {
      background: "radial-gradient(ellipse 70% 55% at 20% 0%, rgba(127,194,224,0.13), transparent 62%)"
    },
    "aria-hidden": "true"
  }), /*#__PURE__*/React.createElement("div", {
    className: "relative z-10 px-8 md:px-16 lg:px-20 py-28"
  }, /*#__PURE__*/React.createElement(motion.div, rise(0), /*#__PURE__*/React.createElement(Kicker, null, t("prj.kicker")), /*#__PURE__*/React.createElement("h2", {
    className: "font-body font-semibold not-italic text-white text-6xl md:text-7xl lg:text-[6rem] leading-[0.9] tracking-[-3px]"
  }, "Woland", /*#__PURE__*/React.createElement("br", null), "Guard"), /*#__PURE__*/React.createElement("p", {
    className: "mt-6 text-sm md:text-base text-white/85 font-body font-light leading-snug max-w-3xl"
  }, t("prj.lede"))), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 md:grid-cols-4 gap-4 mt-12"
  }, stats.map(([value, label], i) => /*#__PURE__*/React.createElement(motion.div, _extends({
    key: label
  }, rise(i * 0.06), {
    className: "liquid-glass rounded-[1.25rem] p-5 flex flex-col justify-end min-h-[136px]"
  }), /*#__PURE__*/React.createElement("div", {
    className: "font-body font-semibold not-italic text-white text-4xl tracking-[-1px] leading-none"
  }, value), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-white/80 font-body font-light mt-2"
  }, label)))), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-1 md:grid-cols-2 gap-6 mt-6 items-start"
  }, shots.map(([src, alt, cap], i) => /*#__PURE__*/React.createElement(motion.figure, _extends({
    key: src
  }, rise(i * 0.08), {
    className: "liquid-glass rounded-[1.25rem] p-2 m-0 flex flex-col"
  }), /*#__PURE__*/React.createElement("img", {
    src: src,
    alt: alt,
    loading: "lazy",
    className: "w-full h-auto rounded-[1rem]"
  }), /*#__PURE__*/React.createElement("figcaption", {
    className: "px-3 py-3 text-xs text-white/70 font-body font-light"
  }, cap)))), /*#__PURE__*/React.createElement(motion.div, _extends({}, rise(0.1), {
    className: "mt-8"
  }), /*#__PURE__*/React.createElement("a", {
    href: "https://github.com/Wo1and29/woland-guard",
    target: "_blank",
    rel: "noopener",
    className: "liquid-glass-strong rounded-full px-5 py-2.5 text-sm font-medium text-white font-body inline-flex items-center gap-2"
  }, t("prj.proof"), /*#__PURE__*/React.createElement(ArrowUpRight, {
    className: "h-5 w-5"
  })))));
}

/* ----------------------------------------------------------- pricing */

function Tier({
  badge,
  title,
  price,
  desc,
  items,
  featured
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: `${featured ? "liquid-glass-strong liquid-glass-signal" : "liquid-glass"} rounded-[1.25rem] p-6 min-h-[420px] h-full flex flex-col`
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-start justify-between gap-3"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-body font-semibold not-italic text-white text-3xl md:text-4xl tracking-[-1px] leading-none"
  }, title), badge ? /*#__PURE__*/React.createElement("span", {
    className: "bg-white text-black rounded-full px-3 py-1 text-[11px] font-semibold font-body whitespace-nowrap"
  }, badge) : null), /*#__PURE__*/React.createElement("div", {
    className: "font-body font-semibold not-italic text-white text-4xl tracking-[-1px] leading-none mt-5"
  }, price), /*#__PURE__*/React.createElement("p", {
    className: "mt-3 text-sm text-white/85 font-body font-light leading-snug max-w-[34ch]"
  }, desc), /*#__PURE__*/React.createElement("div", {
    className: "flex-1"
  }), /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap gap-1.5 mt-6"
  }, items.map(item => /*#__PURE__*/React.createElement("span", {
    key: item,
    className: "liquid-glass rounded-full px-3 py-1 text-[11px] text-white/90 font-body"
  }, item))));
}
function Pricing({
  t
}) {
  return /*#__PURE__*/React.createElement("section", {
    id: "pricing",
    className: "relative w-full bg-black overflow-hidden"
  }, /*#__PURE__*/React.createElement("div", {
    className: "pointer-events-none absolute inset-0 z-0",
    style: {
      background: "radial-gradient(ellipse 60% 50% at 82% 100%, rgba(127,194,224,0.11), transparent 62%)"
    },
    "aria-hidden": "true"
  }), /*#__PURE__*/React.createElement("div", {
    className: "relative z-10 px-8 md:px-16 lg:px-20 py-28"
  }, /*#__PURE__*/React.createElement(motion.div, rise(0), /*#__PURE__*/React.createElement(Kicker, null, t("prc.kicker")), /*#__PURE__*/React.createElement(Display, null, t("prc.h2a"), /*#__PURE__*/React.createElement("br", null), t("prc.h2b"))), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-1 md:grid-cols-3 gap-6 mt-16 items-stretch"
  }, /*#__PURE__*/React.createElement(motion.div, rise(0), /*#__PURE__*/React.createElement(Tier, {
    title: t("prc.t1Title"),
    price: t("prc.t1Price"),
    desc: t("prc.t1Desc"),
    items: [t("prc.t1a"), t("prc.t1b"), t("prc.t1c")]
  })), /*#__PURE__*/React.createElement(motion.div, rise(0.08), /*#__PURE__*/React.createElement(Tier, {
    featured: true,
    badge: t("prc.t2Badge"),
    title: t("prc.t2Title"),
    price: t("prc.t2Price"),
    desc: t("prc.t2Desc"),
    items: [t("prc.t2a"), t("prc.t2b"), t("prc.t2c"), t("prc.t2d")]
  })), /*#__PURE__*/React.createElement(motion.div, rise(0.16), /*#__PURE__*/React.createElement(Tier, {
    title: t("prc.t3Title"),
    price: t("prc.t3Price"),
    desc: t("prc.t3Desc"),
    items: [t("prc.t3a"), t("prc.t3b"), t("prc.t3c")]
  }))), /*#__PURE__*/React.createElement(motion.p, _extends({}, rise(0.1), {
    className: "mt-8 text-sm text-white/60 font-body font-light"
  }), t("prc.note"))));
}

/* ----------------------------------------------------------- contact */

function Contact({
  t
}) {
  const rows = [["Telegram", "@floydark", "https://t.me/floydark"], ["GitHub", "Wo1and29/woland-guard", "https://github.com/Wo1and29/woland-guard"]];
  return /*#__PURE__*/React.createElement("section", {
    id: "contact",
    className: "relative w-full bg-black overflow-hidden"
  }, /*#__PURE__*/React.createElement("div", {
    className: "pointer-events-none absolute inset-0 z-0",
    style: {
      background: "radial-gradient(ellipse 65% 60% at 50% 15%, rgba(127,194,224,0.14), transparent 62%)"
    },
    "aria-hidden": "true"
  }), /*#__PURE__*/React.createElement("div", {
    className: "relative z-10 px-8 md:px-16 lg:px-20 py-28"
  }, /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-1 md:grid-cols-2 gap-12 items-center"
  }, /*#__PURE__*/React.createElement(motion.div, rise(0), /*#__PURE__*/React.createElement(Kicker, null, t("ct.kicker")), /*#__PURE__*/React.createElement(Display, {
    className: "lg:text-[5rem]"
  }, t("ct.h2a"), /*#__PURE__*/React.createElement("br", null), t("ct.h2b")), /*#__PURE__*/React.createElement("p", {
    className: "mt-6 text-sm md:text-base text-white/85 font-body font-light leading-snug max-w-[44ch]"
  }, t("ct.lede"))), /*#__PURE__*/React.createElement(motion.div, _extends({}, rise(0.1), {
    className: "flex flex-col gap-3"
  }), rows.map(([label, value, href]) => /*#__PURE__*/React.createElement("a", {
    key: label,
    href: href,
    target: "_blank",
    rel: "noopener",
    className: "liquid-glass rounded-[1.25rem] px-6 py-5 flex items-center justify-between gap-4"
  }, /*#__PURE__*/React.createElement("span", {
    className: "min-w-0"
  }, /*#__PURE__*/React.createElement("span", {
    className: "block font-mono text-[10px] text-white/50 uppercase tracking-[0.14em]"
  }, label), /*#__PURE__*/React.createElement("span", {
    className: "block font-body font-semibold not-italic text-white text-2xl md:text-3xl tracking-[-1px] leading-tight break-all mt-0.5"
  }, value)), /*#__PURE__*/React.createElement(ArrowUpRight, {
    className: "h-6 w-6 text-signal shrink-0"
  })))))));
}
function Footer({
  t
}) {
  return /*#__PURE__*/React.createElement("footer", {
    className: "relative w-full bg-black px-8 md:px-16 lg:px-20 py-10 border-t border-white/10"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap items-center justify-between gap-4 text-xs text-white/45 font-body"
  }, /*#__PURE__*/React.createElement("span", null, "\xA9 2026 Dr. Woland"), /*#__PURE__*/React.createElement("span", null, t("ft.license"), " ", /*#__PURE__*/React.createElement("a", {
    className: "underline underline-offset-4 hover:text-signal",
    href: "https://github.com/Wo1and29/woland-guard/blob/master/LICENSE",
    target: "_blank",
    rel: "noopener"
  }, "AGPL-3.0-or-later"))));
}

/* --------------------------------------------------------------- app */

function App() {
  const {
    lang,
    setLang,
    t
  } = useT();
  return /*#__PURE__*/React.createElement(MotionConfig, {
    reducedMotion: "user"
  }, /*#__PURE__*/React.createElement("div", {
    className: "bg-black"
  }, /*#__PURE__*/React.createElement(Navbar, {
    lang: lang,
    setLang: setLang,
    t: t
  }), /*#__PURE__*/React.createElement(Hero, {
    t: t
  }), /*#__PURE__*/React.createElement(Services, {
    t: t
  }), /*#__PURE__*/React.createElement(Project, {
    lang: lang,
    t: t
  }), /*#__PURE__*/React.createElement(Pricing, {
    t: t
  }), /*#__PURE__*/React.createElement(Contact, {
    t: t
  }), /*#__PURE__*/React.createElement(Footer, {
    t: t
  })));
}
ReactDOM.createRoot(document.getElementById("root")).render(/*#__PURE__*/React.createElement(App, null));