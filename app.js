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
  "nav.project": { ru: "Проект", en: "Project" },
  "nav.services": { ru: "Услуги", en: "Services" },
  "nav.pricing": { ru: "Тарифы", en: "Pricing" },
  "nav.cta": { ru: "Связаться", en: "Get in touch" },
  "nav.toTop": { ru: "Наверх", en: "Back to top" },
  "hero.badgeChip": { ru: "Open source", en: "Open source" },
  "hero.badge": { ru: "Woland Guard — движок детекции по MITRE ATT&CK, AGPL-3.0", en: "Woland Guard — a MITRE ATT&CK detection engine, AGPL-3.0" },
  "hero.h1": { ru: "Вижу вторжение раньше, чем оно станет инцидентом", en: "See the intrusion before it becomes an incident" },
  "hero.lede": { ru: "Проектирую и внедряю системы обнаружения угроз и аудита для Linux-серверов: правила детекции по MITRE ATT&CK, ролевой доступ, полный журнал решений и Telegram-оповещения с разбором инцидента прямо в чате.", en: "I design and build threat detection and audit systems for Linux servers: detection rules mapped to MITRE ATT&CK, role-based access, a full decision log, and Telegram alerts with incident triage right in the chat." },
  "hero.ctaPrimary": { ru: "Обсудить задачу", en: "Discuss a project" },
  "hero.ctaSecondary": { ru: "Код на GitHub", en: "Code on GitHub" },
  "hero.feedHead": { ru: "уведомление · пример", en: "sample notification" },
  "hero.feedJustNow": { ru: "только что", en: "just now" },
  "hero.feedCaption": { ru: "Так выглядит уведомление оператора — пример, не боевые данные.", en: "This is what an operator's notification looks like — a sample, not live data." },
  "hero.stackNote": { ru: "Собрано на проверенном стеке, без магии", en: "Built on a proven stack, no magic" },
  "hero.watermark": { ru: "Session log · uptime 24/7", en: "Session log · uptime 24/7" },
  "rack.kicker": { ru: "// В реальном времени", en: "// In real time" },
  "rack.title": { ru: "Каждый сервер под наблюдением — крутите и смотрите", en: "Every server, watched — drag to look around" },
  "rack.hint": { ru: "Потяните мышью, чтобы повернуть · клик по точке — детали", en: "Drag to rotate · click a node for details" },
  "svc.kicker": { ru: "// Услуги", en: "// Services" },
  "svc.h2a": { ru: "Защита,", en: "Defence" },
  "svc.h2b": { ru: "которая объясняет себя", en: "that explains itself" },
  "svc.card1Title": { ru: "Мониторинг вторжений", en: "Intrusion monitoring" },
  "svc.card1Desc": { ru: "Детекция подозрительной активности — перебор паролей, вход под root, изменение привилегированных групп — с привязкой к тактикам MITRE ATT&CK.", en: "Detection for suspicious activity — password guessing, root logins, privileged group changes — mapped to MITRE ATT&CK tactics." },
  "svc.card2Title": { ru: "Аудит и трассируемость", en: "Audit and traceability" },
  "svc.card2Desc": { ru: "Журнал, который фиксирует каждое решение системы и оператора и выдерживает разбор инцидента постфактум.", en: "A log that records every decision the system and the operator make, and holds up to a post-incident review." },
  "svc.card3Title": { ru: "Ролевой доступ", en: "Role-based access" },
  "svc.card3Desc": { ru: "Права аналитика и администратора разграничены на уровне каждого действия, а не только страницы интерфейса.", en: "Analyst and administrator permissions separated at the level of each action, not just each page." },
  "svc.card4Title": { ru: "Оповещения и реагирование", en: "Alerting and response" },
  "svc.card4Desc": { ru: "Telegram-бот с кнопками: принять инцидент, закрыть, подготовить блокировку адреса — с одобрением вторым оператором.", en: "A Telegram bot with buttons: take an incident, close it, prepare an IP block — with a second operator's approval." },
  "svc.card5Title": { ru: "Архитектура и ревью", en: "Architecture and review" },
  "svc.card5Desc": { ru: "Бэкенд на FastAPI, SQLAlchemy и PostgreSQL — или разбор существующей системы мониторинга и прямой ответ, что стоит переделать.", en: "Backends on FastAPI, SQLAlchemy and PostgreSQL — or a review of an existing monitoring system and a plain answer on what needs rebuilding." },
  "prj.kicker": { ru: "// Флагманский проект", en: "// Flagship project" },
  "prj.lede": { ru: "Открытая система мониторинга безопасности Linux-серверов, спроектированная и написанная с нуля: движок детекции по MITRE ATT&CK, ролевой доступ, полный audit trail и интерактивный Telegram-бот. Работающая система, а не витрина — с тестами и ревью на каждом шаге.", en: "An open-source Linux server security monitoring system, designed and built from scratch: a detection engine mapped to MITRE ATT&CK, role-based access, a full audit trail, and an interactive Telegram bot. A working system, not a showcase — tested and reviewed at every step." },
  "prj.stat1": { ru: "строк production-кода", en: "lines of production code" },
  "prj.stat2": { ru: "строк тестов", en: "lines of tests" },
  "prj.stat3": { ru: "архитектурных решений в ADR", en: "architecture decisions in ADRs" },
  "prj.stat4": { ru: "открытая лицензия", en: "open license" },
  "prj.shot1Alt": { ru: "Обзор Woland Guard: серверы, активные инциденты и очередь уведомлений", en: "Woland Guard overview: servers, active incidents and the notification queue" },
  "prj.shot1Cap": { ru: "Обзор: серверы, активные инциденты, очередь уведомлений", en: "Overview: servers, active incidents, notification queue" },
  "prj.shot2Alt": { ru: "Список инцидентов Woland Guard с фильтрами, severity и счётчиком evidence", en: "Woland Guard incident list with filters, severity and evidence counts" },
  "prj.shot2Cap": { ru: "Инциденты: фильтры, severity, привязка к версии правила, evidence", en: "Incidents: filters, severity, rule version binding, evidence" },
  "prj.proof": { ru: "Смотреть исходный код", en: "View the source" },
  "prc.kicker": { ru: "// Тарифы", en: "// Pricing" },
  "prc.h2a": { ru: "Прозрачно", en: "Transparent" },
  "prc.h2b": { ru: "как audit trail", en: "like an audit trail" },
  "prc.t1Title": { ru: "Быстрый старт", en: "Quick start" },
  "prc.t1Price": { ru: "от 15 000 ₽", en: "from ₽15,000" },
  "prc.t1Desc": { ru: "Разворачиваю Woland Guard под вашу инфраструктуру: Docker Compose, базовый набор правил детекции, Telegram-оповещения.", en: "I deploy Woland Guard on your infrastructure: Docker Compose, a baseline set of detection rules, Telegram alerts." },
  "prc.t1a": { ru: "До 3 серверов", en: "Up to 3 servers" },
  "prc.t1b": { ru: "Готовые правила детекции", en: "Ready-made detection rules" },
  "prc.t1c": { ru: "Telegram-оповещения", en: "Telegram alerts" },
  "prc.t2Badge": { ru: "Чаще всего выбирают", en: "Most popular" },
  "prc.t2Title": { ru: "Под задачу", en: "Custom fit" },
  "prc.t2Price": { ru: "от 40 000 ₽", en: "from ₽40,000" },
  "prc.t2Desc": { ru: "Кастомные правила детекции под ваши риски, ролевой доступ под структуру команды, полный audit trail.", en: "Custom detection rules for your risks, role-based access matching your team's structure, a full audit trail." },
  "prc.t2a": { ru: "До 10 серверов", en: "Up to 10 servers" },
  "prc.t2b": { ru: "Правила под ваши риски", en: "Rules for your risks" },
  "prc.t2c": { ru: "Ролевой доступ и аудит", en: "Role-based access and audit" },
  "prc.t2d": { ru: "Интерактивный Telegram-бот", en: "Interactive Telegram bot" },
  "prc.t3Title": { ru: "Индивидуальная разработка", en: "Custom build" },
  "prc.t3Price": { ru: "по ТЗ", en: "quote on request" },
  "prc.t3Desc": { ru: "Проектирую и разрабатываю систему безопасности с нуля: собственная архитектура, интеграции, перенос существующих логов.", en: "I design and build a security system from scratch: its own architecture, integrations, migrating existing logs." },
  "prc.t3a": { ru: "Архитектура под требования", en: "Architecture built to your requirements" },
  "prc.t3b": { ru: "Интеграция с вашими системами", en: "Integration with your systems" },
  "prc.t3c": { ru: "Консультации по ходу проекта", en: "Consulting throughout the project" },
  "prc.note": { ru: "Итоговая стоимость зависит от инфраструктуры и объёма работ — обсуждаем до начала.", en: "Final cost depends on your infrastructure and scope — we discuss it before starting." },
  "ct.kicker": { ru: "// Связь", en: "// Contact" },
  "ct.h2a": { ru: "Обсудим вашу", en: "Let's talk about" },
  "ct.h2b": { ru: "инфраструктуру", en: "your infrastructure" },
  "ct.lede": { ru: "Расскажите, что нужно защитить и от чего — отвечу и предложу вариант решения.", en: "Tell me what needs protecting and from what — I'll reply with a proposed approach." },
  "ft.license": { ru: "Woland Guard распространяется по лицензии", en: "Woland Guard is licensed under" }
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
  return { lang, setLang, t };
}

/* --------------------------------------------------- SignalField canvas */

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
    let W = 0, H = 0, DPR = 1, nodes = [], t = 0, scanY = 0, raf = null;
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
      W = rect.width; H = rect.height;
      canvas.width = W * DPR; canvas.height = H * DPR;
      canvas.style.width = W + "px"; canvas.style.height = H + "px";
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      buildNodes();
    };
    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      ctx.lineWidth = 1;
      for (let i = 0; i < nodes.length; i++) {
        for (let k = i + 1; k < nodes.length; k++) {
          const a = nodes[i], b = nodes[k];
          const dx = a.x - b.x, dy = a.y - b.y;
          const d = Math.sqrt(dx * dx + dy * dy);
          if (d < 95) {
            ctx.globalAlpha = (1 - d / 95) * 0.5;
            ctx.strokeStyle = "rgba(127,194,224,0.16)";
            ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
          }
        }
      }
      ctx.globalAlpha = 1;
      for (const node of nodes) {
        const pulse = 0.5 + 0.5 * Math.sin(t * 0.02 + node.phase);
        const r = node.alert ? 2.1 + pulse * 1.5 : 1.3;
        ctx.beginPath();
        ctx.fillStyle = node.alert ? "rgba(226,105,90," + (0.4 + pulse * 0.5) + ")" : "rgba(127,194,224," + (0.28 + pulse * 0.28) + ")";
        ctx.arc(node.x, node.y, r, 0, Math.PI * 2); ctx.fill();
      }
      ctx.fillStyle = "rgba(127,194,224,0.05)";
      ctx.fillRect(0, scanY - 46, W, 92);
      ctx.strokeStyle = "rgba(127,194,224,0.3)";
      ctx.beginPath(); ctx.moveTo(0, scanY); ctx.lineTo(W, scanY); ctx.stroke();
    };
    const loop = () => {
      t++; scanY += scanSpeed;
      if (scanY > H + 46) scanY = -46;
      draw();
      raf = requestAnimationFrame(loop);
    };
    window.addEventListener("resize", resize);
    resize();
    scanY = H * 0.3;
    if (reduced) draw(); else raf = requestAnimationFrame(loop);
    return () => {
      window.removeEventListener("resize", resize);
      if (raf) cancelAnimationFrame(raf);
    };
  }, [density, scanSpeed, alertRate]);
  return /*#__PURE__*/React.createElement("canvas", {
    ref: canvasRef,
    "aria-hidden": "true",
    className: "absolute inset-0 w-full h-full block z-0",
    style: { opacity }
  });
}

/* ------------------------------------------------------------ ShieldCanvas
   A rotating 3D shield-and-key mesh in the hero, built from a THREE.Shape
   extrusion so it stays a thin outlined solid rather than a flat icon. */

function ShieldCanvas() {
  const canvasRef = useRef(null);
  const pointerRef = useRef({ x: 0, y: 0 });
  useEffect(() => {
    let raf = null;
    let cancelled = false;
    const onMove = e => {
      pointerRef.current = { x: e.clientX / window.innerWidth - 0.5, y: e.clientY / window.innerHeight - 0.5 };
    };
    window.addEventListener("pointermove", onMove);
    const reduced = reducedMotion();
    const init = attempt => {
      if (cancelled) return;
      if (!window.THREE) {
        if (attempt < 20) setTimeout(() => init(attempt + 1), 150);
        return;
      }
      const canvas = canvasRef.current;
      if (!canvas) return;
      const THREE = window.THREE;
      const rect = canvas.parentElement.getBoundingClientRect();
      const size = Math.min(rect.width, 420) || 320;
      const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      renderer.setSize(size, size, false);

      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(32, 1, 0.1, 100);
      camera.position.set(0, 0, 6.2);

      const shape = new THREE.Shape();
      shape.moveTo(-1, 1.1);
      shape.lineTo(1, 1.1);
      shape.lineTo(1, 0.15);
      shape.bezierCurveTo(1, -0.75, 0.55, -1.15, 0, -1.55);
      shape.bezierCurveTo(-0.55, -1.15, -1, -0.75, -1, 0.15);
      shape.closePath();
      const hole = new THREE.Path();
      hole.absarc(0, 0.15, 0.26, 0, Math.PI * 2, false);
      shape.holes.push(hole);
      const keyStem = new THREE.Path();
      keyStem.moveTo(-0.075, -0.42);
      keyStem.lineTo(0.075, -0.42);
      keyStem.lineTo(0.075, -0.02);
      keyStem.lineTo(-0.075, -0.02);
      keyStem.closePath();
      shape.holes.push(keyStem);

      const geometry = new THREE.ExtrudeGeometry(shape, { depth: 0.3, bevelEnabled: true, bevelThickness: 0.04, bevelSize: 0.03, bevelSegments: 2, curveSegments: 24 });
      geometry.center();
      const material = new THREE.MeshStandardMaterial({ color: 0x0b0d10, metalness: 0.65, roughness: 0.32 });
      const mesh = new THREE.Mesh(geometry, material);
      scene.add(mesh);

      const edges = new THREE.EdgesGeometry(geometry, 24);
      const lineMat = new THREE.LineBasicMaterial({ color: 0x7fc2e0, transparent: true, opacity: 0.85 });
      mesh.add(new THREE.LineSegments(edges, lineMat));

      scene.add(new THREE.AmbientLight(0x22303a, 1.6));
      const key = new THREE.DirectionalLight(0x7fc2e0, 1.4);
      key.position.set(2, 3, 4);
      scene.add(key);
      const fill = new THREE.PointLight(0x7fc2e0, 3, 12);
      fill.position.set(-2, -1, 3);
      scene.add(fill);

      const animate = () => {
        mesh.rotation.y += reduced ? 0 : 0.0035;
        const p = pointerRef.current;
        mesh.rotation.x += (-p.y * 0.5 - mesh.rotation.x) * 0.04;
        mesh.rotation.z += (p.x * 0.25 - mesh.rotation.z) * 0.04;
        renderer.render(scene, camera);
        raf = requestAnimationFrame(animate);
      };
      animate();
    };
    init(0);
    return () => {
      cancelled = true;
      window.removeEventListener("pointermove", onMove);
      if (raf) cancelAnimationFrame(raf);
    };
  }, []);
  return /*#__PURE__*/React.createElement("canvas", {
    ref: canvasRef,
    "aria-hidden": "true",
    className: "absolute z-[1] pointer-events-none",
    style: {
      top: "clamp(90px,14vh,180px)",
      right: "clamp(-40px,2vw,80px)",
      width: "min(46vw,420px)",
      height: "min(46vw,420px)",
      opacity: 0.9
    }
  });
}

/* ----------------------------------------------------- NetworkSection
   A promoted mid-page section: a sphere of server nodes with a rotating
   core. Drag to orbit; click a node to read its status in a popup that
   tracks the node's projected screen position every frame. */

const SEV_COLOR = {
  critical: { color: "#e2695a" },
  warning: { color: "#dba55a" },
  info: { color: "#93aec2" },
  ok: { color: "#7fc2e0" }
};
const NODE_INFO = [
  { host: "db-primary-01", event: "ssh_root_login_success", sev: "critical" },
  { host: "bastion-eu-west-1", event: "ssh_bruteforce_by_ip", sev: "warning" },
  { host: "api-gateway-02", event: "user_account_created", sev: "info" },
  { host: "web-frontend-01", event: "privileged_group_membership_changed", sev: "warning" },
  { host: "cache-eu-1", event: "heartbeat: ok", sev: "ok" },
  { host: "worker-03", event: "heartbeat: ok", sev: "ok" }
];

function NetworkSection({ t }) {
  const wrapRef = useRef(null);
  const canvasRef = useRef(null);
  const popupRef = useRef(null);
  const [popup, setPopup] = useState(null);

  useEffect(() => {
    let raf = null;
    let cancelled = false;
    const cleanups = [];
    const reduced = reducedMotion();
    const rackRot = { x: -0.15, y: 0.5 };
    const drag = { active: false, lastX: 0, lastY: 0, startX: 0, startY: 0 };
    const selectedRef = { current: null };

    const init = attempt => {
      if (cancelled) return;
      if (!window.THREE) {
        if (attempt < 20) setTimeout(() => init(attempt + 1), 150);
        return;
      }
      const canvas = canvasRef.current;
      const wrap = wrapRef.current;
      if (!canvas || !wrap) return;
      const THREE = window.THREE;
      const rect = wrap.getBoundingClientRect();
      const w = rect.width, h = rect.height;
      const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      renderer.setSize(w, h, false);

      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(34, w / h, 0.1, 100);
      camera.position.set(0, 0, 7.5);

      const group = new THREE.Group();
      scene.add(group);

      const N = 46, R = 2.05;
      const pts = [];
      const golden = Math.PI * (3 - Math.sqrt(5));
      for (let i = 0; i < N; i++) {
        const yv = 1 - i / (N - 1) * 2;
        const rad = Math.sqrt(1 - yv * yv);
        const theta = golden * i;
        pts.push(new THREE.Vector3(Math.cos(theta) * rad * R, yv * R, Math.sin(theta) * rad * R));
      }
      const alertIdx = new Set([3, 14, 27, 39]);
      const nodeMeshes = [];
      for (let i = 0; i < pts.length; i++) {
        const isAlert = alertIdx.has(i);
        const geo = new THREE.SphereGeometry(isAlert ? 0.075 : 0.045, 12, 12);
        const mat = new THREE.MeshBasicMaterial({ color: isAlert ? 0xe2695a : 0x7fc2e0, transparent: true, opacity: isAlert ? 0.95 : 0.75 });
        const node = new THREE.Mesh(geo, mat);
        node.position.copy(pts[i]);
        node.userData = {
          base: isAlert ? 0.075 : 0.045,
          phase: Math.random() * Math.PI * 2,
          alert: isAlert,
          info: isAlert ? NODE_INFO[i % 4] : NODE_INFO[4 + i % 2]
        };
        group.add(node);
        nodeMeshes.push(node);
      }
      const raycaster = new THREE.Raycaster();
      raycaster.params.Points = { threshold: 0.12 };
      const mouseVec = new THREE.Vector2();

      const lineMat = new THREE.LineBasicMaterial({ color: 0x7fc2e0, transparent: true, opacity: 0.16 });
      const linePositions = [];
      for (let i = 0; i < pts.length; i++) {
        for (let k = i + 1; k < pts.length; k++) {
          if (pts[i].distanceTo(pts[k]) < 1.05) {
            linePositions.push(pts[i].x, pts[i].y, pts[i].z, pts[k].x, pts[k].y, pts[k].z);
          }
        }
      }
      const lineGeo = new THREE.BufferGeometry();
      lineGeo.setAttribute("position", new THREE.Float32BufferAttribute(linePositions, 3));
      group.add(new THREE.LineSegments(lineGeo, lineMat));

      const coreGeo = new THREE.IcosahedronGeometry(0.5, 1);
      const coreMat = new THREE.MeshStandardMaterial({ color: 0x0b0d10, metalness: 0.6, roughness: 0.35 });
      const core = new THREE.Mesh(coreGeo, coreMat);
      group.add(core);
      core.add(new THREE.LineSegments(new THREE.EdgesGeometry(coreGeo), new THREE.LineBasicMaterial({ color: 0x7fc2e0, transparent: true, opacity: 0.55 })));

      scene.add(new THREE.AmbientLight(0x22303a, 1.5));
      const key = new THREE.DirectionalLight(0x7fc2e0, 1.3);
      key.position.set(3, 4, 5);
      scene.add(key);
      const fill = new THREE.PointLight(0x7fc2e0, 2.5, 14);
      fill.position.set(-3, -2, 4);
      scene.add(fill);

      group.rotation.x = rackRot.x;
      group.rotation.y = rackRot.y;

      const onDown = e => {
        drag.active = true;
        drag.lastX = e.clientX; drag.lastY = e.clientY;
        drag.startX = e.clientX; drag.startY = e.clientY;
        wrap.style.cursor = "grabbing";
      };
      const onMove = e => {
        if (!drag.active) return;
        const dx = e.clientX - drag.lastX, dy = e.clientY - drag.lastY;
        rackRot.y += dx * 0.008;
        rackRot.x = Math.max(-0.9, Math.min(0.9, rackRot.x + dy * 0.008));
        drag.lastX = e.clientX; drag.lastY = e.clientY;
      };
      const onUp = e => {
        const moved = Math.abs(e.clientX - drag.startX) + Math.abs(e.clientY - drag.startY);
        drag.active = false;
        wrap.style.cursor = "grab";
        if (moved < 6) {
          const cr = canvas.getBoundingClientRect();
          mouseVec.x = (e.clientX - cr.left) / cr.width * 2 - 1;
          mouseVec.y = -((e.clientY - cr.top) / cr.height) * 2 + 1;
          raycaster.setFromCamera(mouseVec, camera);
          const hit = raycaster.intersectObjects(nodeMeshes)[0];
          if (hit) {
            selectedRef.current = hit.object;
            setPopup({ info: hit.object.userData.info, sevColor: SEV_COLOR[hit.object.userData.info.sev].color });
          } else {
            selectedRef.current = null;
            setPopup(null);
          }
        }
      };
      wrap.addEventListener("pointerdown", onDown);
      wrap.addEventListener("pointermove", onMove);
      wrap.addEventListener("pointerup", onUp);
      wrap.addEventListener("pointerleave", onUp);
      cleanups.push(() => {
        wrap.removeEventListener("pointerdown", onDown);
        wrap.removeEventListener("pointermove", onMove);
        wrap.removeEventListener("pointerup", onUp);
        wrap.removeEventListener("pointerleave", onUp);
      });

      let tt = 0;
      const projVec = new THREE.Vector3();
      const animate = () => {
        tt++;
        if (!drag.active && !reduced && !selectedRef.current) rackRot.y += 0.0022;
        group.rotation.x += (rackRot.x - group.rotation.x) * 0.15;
        group.rotation.y += (rackRot.y - group.rotation.y) * 0.15;
        if (!reduced) {
          for (const n of nodeMeshes) {
            const pulse = 0.5 + 0.5 * Math.sin(tt * 0.03 + n.userData.phase);
            const s = n.userData.base * (n.userData.alert ? 0.8 + pulse * 0.6 : 0.9 + pulse * 0.25);
            n.scale.setScalar(s / n.userData.base);
          }
        }
        renderer.render(scene, camera);
        if (selectedRef.current && popupRef.current) {
          projVec.setFromMatrixPosition(selectedRef.current.matrixWorld);
          projVec.project(camera);
          const x = (projVec.x * 0.5 + 0.5) * canvas.clientWidth;
          const y = (-projVec.y * 0.5 + 0.5) * canvas.clientHeight;
          popupRef.current.style.left = x + "px";
          popupRef.current.style.top = y + "px";
        }
        raf = requestAnimationFrame(animate);
      };
      animate();
    };
    init(0);
    return () => {
      cancelled = true;
      if (raf) cancelAnimationFrame(raf);
      cleanups.forEach(fn => fn());
    };
  }, []);

  const closePopup = () => setPopup(null);

  return /*#__PURE__*/React.createElement("section", {
    id: "rack",
    className: "relative w-full overflow-hidden bg-black"
  }, /*#__PURE__*/React.createElement("div", {
    className: "pointer-events-none absolute inset-0 z-0",
    style: { background: "radial-gradient(ellipse 60% 55% at 50% 40%, rgba(127,194,224,0.09), transparent 65%)" },
    "aria-hidden": "true"
  }), /*#__PURE__*/React.createElement("div", {
    className: "relative z-10 px-8 md:px-16 lg:px-20 py-20 flex flex-col items-center text-center"
  }, /*#__PURE__*/React.createElement(Kicker, null, t("rack.kicker")),
     /*#__PURE__*/React.createElement("h2", {
    className: "font-body font-semibold not-italic text-white text-3xl md:text-5xl leading-tight tracking-[-1px] max-w-2xl"
  }, t("rack.title")),
     /*#__PURE__*/React.createElement("div", {
    ref: wrapRef,
    className: "relative mt-10 w-full max-w-xl",
    style: { height: "min(56vw,420px)", cursor: "grab", touchAction: "none" }
  }, /*#__PURE__*/React.createElement("canvas", { ref: canvasRef, className: "w-full h-full block" }),
     popup && /*#__PURE__*/React.createElement("div", {
    ref: popupRef,
    className: "liquid-glass liquid-glass-signal absolute rounded-xl px-3.5 py-2.5 text-left z-20",
    style: { left: 0, top: 0, transform: "translate(-50%,-130%)", minWidth: 200, cursor: "auto" }
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-between gap-3"
  }, /*#__PURE__*/React.createElement("span", {
    className: "font-mono text-xs text-white"
  }, popup.info.host), /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: closePopup,
    className: "text-white/50 leading-none text-sm"
  }, "\u00D7")), /*#__PURE__*/React.createElement("div", {
    className: "mt-1.5 font-mono text-[10px] uppercase tracking-[0.05em]",
    style: { color: popup.sevColor }
  }, popup.info.sev), /*#__PURE__*/React.createElement("div", {
    className: "mt-1 font-mono text-[11px] text-white/85 break-all"
  }, popup.info.event))),
     /*#__PURE__*/React.createElement("p", {
    className: "mt-4 font-mono text-[11px] uppercase tracking-[0.08em] text-white/35"
  }, t("rack.hint"))));
}

/* ---------------------------------------------------------- BlurText */

function BlurText({
  text,
  className
}) {
  const ref = useRef(null);
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
    }, { threshold: 0.1 });
    io.observe(el);
    return () => io.disconnect();
  }, []);
  const words = text.split(" ");
  return /*#__PURE__*/React.createElement("h1", {
    ref: ref,
    className: className,
    style: { display: "flex", flexWrap: "wrap", justifyContent: "center", rowGap: "0.1em" }
  }, words.map((word, i) => /*#__PURE__*/React.createElement(motion.span, {
    key: `${word}-${i}`,
    initial: { filter: "blur(10px)", opacity: 0, y: 50 },
    animate: inView ? { filter: ["blur(10px)", "blur(5px)", "blur(0px)"], opacity: [0, 0.5, 1], y: [50, -5, 0] } : {},
    transition: { duration: 0.7, times: [0, 0.5, 1], ease: "easeOut", delay: i * 100 / 1000 },
    style: { display: "inline-block", marginRight: "0.28em" }
  }, word)));
}

/* ------------------------------------------------------------ shared */

const rise = delay => ({
  initial: { filter: "blur(10px)", opacity: 0, y: 20 },
  whileInView: { filter: "blur(0px)", opacity: 1, y: 0 },
  viewport: { once: true, amount: 0.2 },
  transition: { duration: 0.6, ease: "easeOut", delay }
});
const riseNow = delay => ({
  initial: { filter: "blur(10px)", opacity: 0, y: 20 },
  animate: { filter: "blur(0px)", opacity: 1, y: 0 },
  transition: { duration: 0.6, ease: "easeOut", delay }
});
function Kicker({ children }) {
  return /*#__PURE__*/React.createElement("p", {
    className: "text-sm font-mono text-signal/90 mb-6 tracking-[0.06em]"
  }, children);
}
function Display({ children, className = "" }) {
  return /*#__PURE__*/React.createElement("h2", {
    className: `font-body font-semibold not-italic text-white text-6xl md:text-7xl lg:text-[6rem] leading-[0.9] tracking-[-3px] break-words ${className}`
  }, children);
}

/* ------------------------------------------------------------ navbar */

function Navbar({ lang, setLang, t }) {
  const links = [["#project", t("nav.project")], ["#services", t("nav.services")], ["#pricing", t("nav.pricing")]];
  const toggle = () => setLang(lang === "ru" ? "en" : "ru");
  const toTop = event => {
    event.preventDefault();
    window.scrollTo({ top: 0, behavior: reducedMotion() ? "auto" : "smooth" });
  };
  return /*#__PURE__*/React.createElement("div", {
    className: "fixed top-4 left-0 right-0 z-50 px-8 lg:px-16"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-between gap-4"
  }, /*#__PURE__*/React.createElement("a", {
    href: "#top", onClick: toTop, title: t("nav.toTop"), "aria-label": t("nav.toTop"),
    className: "liquid-glass liquid-glass-signal h-12 w-12 shrink-0 rounded-full flex items-center justify-center"
  }, /*#__PURE__*/React.createElement("span", {
    className: "font-body font-semibold not-italic text-white text-2xl leading-none"
  }, "w")), /*#__PURE__*/React.createElement("div", {
    className: "hidden md:flex items-center"
  }, /*#__PURE__*/React.createElement("div", {
    className: "liquid-glass rounded-full px-1.5 py-1.5 flex items-center"
  }, links.map(([href, label]) => /*#__PURE__*/React.createElement("a", {
    key: href, href: href,
    className: "px-3 py-2 text-sm font-medium text-white/90 font-body hover:text-white"
  }, label)), /*#__PURE__*/React.createElement("button", {
    type: "button", onClick: toggle,
    "aria-label": "Switch language / \u041F\u0435\u0440\u0435\u043A\u043B\u044E\u0447\u0438\u0442\u044C \u044F\u0437\u044B\u043A",
    className: "mx-1 px-3 py-2 text-sm font-medium font-mono text-white/60 hover:text-signal"
  }, lang === "ru" ? "EN" : "RU"), /*#__PURE__*/React.createElement("a", {
    href: "#contact",
    className: "bg-white text-black rounded-full px-4 py-2 text-sm font-medium font-body inline-flex items-center gap-1.5 whitespace-nowrap"
  }, t("nav.cta"), /*#__PURE__*/React.createElement(ArrowUpRight, { className: "h-4 w-4" })))),
     /*#__PURE__*/React.createElement("div", {
    className: "md:hidden flex items-center gap-2"
  }, /*#__PURE__*/React.createElement("button", {
    type: "button", onClick: toggle,
    "aria-label": "Switch language / \u041F\u0435\u0440\u0435\u043A\u043B\u044E\u0447\u0438\u0442\u044C \u044F\u0437\u044B\u043A",
    className: "liquid-glass rounded-full px-4 h-12 text-sm font-medium font-mono text-white"
  }, lang === "ru" ? "EN" : "RU"), /*#__PURE__*/React.createElement("a", {
    href: "#contact",
    className: "bg-white text-black rounded-full px-4 h-12 text-sm font-medium font-body inline-flex items-center whitespace-nowrap"
  }, t("nav.cta"))), /*#__PURE__*/React.createElement("div", {
    className: "hidden md:block h-12 w-12 shrink-0", "aria-hidden": "true"
  })));
}

/* ------------------------------------------------------- incident feed */

const SEV_STYLE = {
  critical: "text-critical bg-critical/15",
  warning: "text-warning bg-warning/15",
  info: "text-info bg-info/15"
};
const FEED = [["critical", "ssh_root_login_success", "T1078 · Valid Accounts", "db-primary-01", "02:14:07"], ["warning", "ssh_bruteforce_by_ip", "T1110 · Brute Force", "bastion-eu-west-1", "01:52:33"], ["info", "user_account_created", "T1136 · Create Account", "api-gateway-02", "00:47:11"]];
function IncidentFeed({ t }) {
  const [incoming, setIncoming] = useState(reducedMotion());
  useEffect(() => {
    if (reducedMotion()) return;
    const id = setTimeout(() => setIncoming(true), 1900);
    return () => clearTimeout(id);
  }, []);
  const Row = ({ sev, rule, tactic, host, time, dim }) => /*#__PURE__*/React.createElement("div", {
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
    key: rule, sev: sev, rule: rule, tactic: tactic, host: host, time: time
  })), /*#__PURE__*/React.createElement(Row, {
    sev: "warning", rule: "privileged_group_membership_changed", tactic: "T1098 \xB7 Account Manipulation",
    host: "web-frontend-01", time: t("hero.feedJustNow"), dim: !incoming
  }), /*#__PURE__*/React.createElement("div", {
    className: "px-4 py-3 border-t border-white/10 text-[11px] text-white/40 font-body font-light"
  }, t("hero.feedCaption")));
}

/* -------------------------------------------------------------- hero */

function Hero({ t }) {
  const stack = ["FastAPI", "PostgreSQL", "SQLAlchemy", "Telegram", "Docker"];
  return /*#__PURE__*/React.createElement("section", {
    id: "top",
    className: "relative min-h-screen w-full overflow-hidden bg-black"
  }, /*#__PURE__*/React.createElement(SignalField, { density: 74, opacity: 0.65 }),
     /*#__PURE__*/React.createElement(ShieldCanvas, null),
     /*#__PURE__*/React.createElement("div", {
    className: "pointer-events-none absolute inset-0 z-[1]",
    style: { background: "radial-gradient(ellipse 60% 55% at 50% 12%, rgba(127,194,224,0.16), transparent 62%)" },
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
    key: t("hero.h1"), text: t("hero.h1"),
    className: "mt-6 text-5xl md:text-7xl lg:text-[5.5rem] font-body font-semibold not-italic text-white leading-[0.8] max-w-3xl justify-center tracking-[-4px]"
  }), /*#__PURE__*/React.createElement(motion.p, _extends({}, riseNow(0.8), {
    className: "mt-5 text-sm md:text-base text-white/85 max-w-2xl font-body font-light leading-snug"
  }), t("hero.lede")), /*#__PURE__*/React.createElement(motion.div, _extends({}, riseNow(1.1), {
    className: "flex items-center gap-6 mt-7"
  }), /*#__PURE__*/React.createElement("a", {
    href: "#contact",
    className: "liquid-glass-strong rounded-full px-5 py-2.5 text-sm font-medium text-white font-body inline-flex items-center gap-2"
  }, t("hero.ctaPrimary"), /*#__PURE__*/React.createElement(ArrowUpRight, { className: "h-5 w-5" })), /*#__PURE__*/React.createElement("a", {
    href: "https://github.com/Wo1and29/woland-guard", target: "_blank", rel: "noopener",
    className: "text-sm font-medium text-white font-body inline-flex items-center gap-2 hover:text-signal"
  }, t("hero.ctaSecondary"), /*#__PURE__*/React.createElement(ArrowUpRight, { className: "h-4 w-4" }))), /*#__PURE__*/React.createElement(motion.div, _extends({}, riseNow(1.3), {
    className: "mt-10 w-full flex justify-center"
  }), /*#__PURE__*/React.createElement(IncidentFeed, { t: t }))), /*#__PURE__*/React.createElement(motion.div, _extends({}, riseNow(1.5), {
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

function ServiceCard({ iconPath, tags, title, body }) {
  return /*#__PURE__*/React.createElement("div", {
    className: "liquid-glass rounded-[1.25rem] p-6 min-h-[360px] h-full flex flex-col"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-start justify-between gap-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "liquid-glass liquid-glass-signal h-11 w-11 shrink-0 rounded-[0.75rem] flex items-center justify-center"
  }, /*#__PURE__*/React.createElement(MaterialIcon, { d: iconPath })), /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap justify-end gap-1.5 max-w-[70%]"
  }, tags.map(tag => /*#__PURE__*/React.createElement("span", {
    key: tag,
    className: "liquid-glass rounded-full px-3 py-1 text-[11px] text-white/90 font-mono whitespace-nowrap"
  }, tag)))), /*#__PURE__*/React.createElement("div", { className: "flex-1" }), /*#__PURE__*/React.createElement("div", {
    className: "mt-6"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-body font-semibold not-italic text-white text-3xl md:text-4xl tracking-[-1px] leading-none"
  }, title), /*#__PURE__*/React.createElement("p", {
    className: "mt-3 text-sm text-white/85 font-body font-light leading-snug max-w-[34ch]"
  }, body)));
}
function Services({ t }) {
  const cards = [{
    iconPath: ICON.shield, tags: ["TA0006", "Credential Access", "sshd", "auditd"], title: t("svc.card1Title"), body: t("svc.card1Desc")
  }, {
    iconPath: ICON.history, tags: ["TA0005", "Defense Evasion", "Audit trail"], title: t("svc.card2Title"), body: t("svc.card2Desc")
  }, {
    iconPath: ICON.key, tags: ["TA0004", "Privilege Escalation", "RBAC"], title: t("svc.card3Title"), body: t("svc.card3Desc")
  }, {
    iconPath: ICON.bell, tags: ["Telegram Bot API", "Four-eyes", "Inline keyboard"], title: t("svc.card4Title"), body: t("svc.card4Desc")
  }, {
    iconPath: ICON.storage, tags: ["FastAPI", "SQLAlchemy", "PostgreSQL", "Alembic"], title: t("svc.card5Title"), body: t("svc.card5Desc")
  }];
  return /*#__PURE__*/React.createElement("section", {
    id: "services",
    className: "relative min-h-screen w-full overflow-hidden bg-black"
  }, /*#__PURE__*/React.createElement(SignalField, { density: 96, scanSpeed: 0.35, alertRate: 0.03, opacity: 0.5 }), /*#__PURE__*/React.createElement("div", {
    className: "pointer-events-none absolute inset-0 z-[1]",
    style: { background: "radial-gradient(ellipse 70% 60% at 15% 0%, rgba(127,194,224,0.12), transparent 60%)" },
    "aria-hidden": "true"
  }), /*#__PURE__*/React.createElement("div", {
    className: "relative z-10 px-8 md:px-16 lg:px-20 pt-28 pb-16 flex flex-col min-h-screen"
  }, /*#__PURE__*/React.createElement(motion.div, _extends({}, rise(0), { className: "mb-auto" }), /*#__PURE__*/React.createElement(Kicker, null, t("svc.kicker")), /*#__PURE__*/React.createElement(Display, null, t("svc.h2a"), /*#__PURE__*/React.createElement("br", null), t("svc.h2b"))), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mt-16"
  }, cards.map((card, i) => /*#__PURE__*/React.createElement(motion.div, _extends({ key: card.title }, rise(i * 0.07)), /*#__PURE__*/React.createElement(ServiceCard, card))))));
}

/* ----------------------------------------------------------- project */

function useCountUp(targets, active) {
  const [vals, setVals] = useState(targets.map(() => 0));
  useEffect(() => {
    if (!active) return;
    if (reducedMotion()) { setVals(targets); return; }
    const start = performance.now();
    const dur = 1300;
    let raf = null;
    const tick = now => {
      const p = Math.min(1, (now - start) / dur);
      const ease = 1 - Math.pow(1 - p, 3);
      setVals(targets.map(v => Math.round(v * ease)));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => { if (raf) cancelAnimationFrame(raf); };
  }, [active]);
  return vals;
}

function Project({ lang, t }) {
  const statsRef = useRef(null);
  const [active, setActive] = useState(!("IntersectionObserver" in window));
  useEffect(() => {
    const el = statsRef.current;
    if (!el || !("IntersectionObserver" in window)) return;
    const io = new IntersectionObserver(entries => {
      entries.forEach(e => { if (e.isIntersecting) { setActive(true); io.disconnect(); } });
    }, { threshold: 0.3 });
    io.observe(el);
    return () => io.disconnect();
  }, []);
  const targets = [23500, 24500, 16];
  const counted = useCountUp(targets, active);
  const stats = [
    [counted[0].toLocaleString("ru-RU") + "+", t("prj.stat1")],
    [counted[1].toLocaleString("ru-RU") + "+", t("prj.stat2")],
    [String(counted[2]), t("prj.stat3")],
    ["AGPL-3.0", t("prj.stat4")]
  ];
  const suffix = lang === "en" ? "_en" : "";
  const shots = [[`shot1${suffix}.png`, t("prj.shot1Alt"), t("prj.shot1Cap")], [`shot2${suffix}.png`, t("prj.shot2Alt"), t("prj.shot2Cap")]];
  return /*#__PURE__*/React.createElement("section", {
    id: "project",
    className: "relative w-full bg-black overflow-hidden"
  }, /*#__PURE__*/React.createElement("div", {
    className: "pointer-events-none absolute inset-0 z-0",
    style: { background: "radial-gradient(ellipse 70% 55% at 20% 0%, rgba(127,194,224,0.13), transparent 62%)" },
    "aria-hidden": "true"
  }), /*#__PURE__*/React.createElement("div", {
    className: "relative z-10 px-8 md:px-16 lg:px-20 py-28"
  }, /*#__PURE__*/React.createElement(motion.div, rise(0), /*#__PURE__*/React.createElement(Kicker, null, t("prj.kicker")), /*#__PURE__*/React.createElement("h2", {
    className: "font-body font-semibold not-italic text-white text-6xl md:text-7xl lg:text-[6rem] leading-[0.9] tracking-[-3px]"
  }, "Woland", /*#__PURE__*/React.createElement("br", null), "Guard"), /*#__PURE__*/React.createElement("p", {
    className: "mt-6 text-sm md:text-base text-white/85 font-body font-light leading-snug max-w-3xl"
  }, t("prj.lede"))), /*#__PURE__*/React.createElement("div", {
    ref: statsRef,
    className: "grid grid-cols-2 md:grid-cols-4 gap-4 mt-12"
  }, stats.map(([value, label], i) => /*#__PURE__*/React.createElement(motion.div, _extends({ key: label }, rise(i * 0.06), {
    className: "liquid-glass rounded-[1.25rem] p-5 flex flex-col justify-end min-h-[136px]"
  }), /*#__PURE__*/React.createElement("div", {
    className: "font-body font-semibold not-italic text-white text-4xl tracking-[-1px] leading-none"
  }, value), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-white/80 font-body font-light mt-2"
  }, label)))), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-1 md:grid-cols-2 gap-6 mt-6 items-start"
  }, shots.map(([src, alt, cap], i) => /*#__PURE__*/React.createElement(motion.figure, _extends({ key: src }, rise(i * 0.08), {
    className: "liquid-glass rounded-[1.25rem] p-2 m-0 flex flex-col"
  }), /*#__PURE__*/React.createElement("img", {
    src: src, alt: alt, loading: "lazy", className: "w-full h-auto rounded-[1rem]"
  }), /*#__PURE__*/React.createElement("figcaption", {
    className: "px-3 py-3 text-xs text-white/70 font-body font-light"
  }, cap)))), /*#__PURE__*/React.createElement(motion.div, _extends({}, rise(0.1), { className: "mt-8" }), /*#__PURE__*/React.createElement("a", {
    href: "https://github.com/Wo1and29/woland-guard", target: "_blank", rel: "noopener",
    className: "liquid-glass-strong rounded-full px-5 py-2.5 text-sm font-medium text-white font-body inline-flex items-center gap-2"
  }, t("prj.proof"), /*#__PURE__*/React.createElement(ArrowUpRight, { className: "h-5 w-5" })))));
}

/* ----------------------------------------------------------- pricing */

function Tier({ badge, title, price, desc, items, featured }) {
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
  }, desc), /*#__PURE__*/React.createElement("div", { className: "flex-1" }), /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap gap-1.5 mt-6"
  }, items.map(item => /*#__PURE__*/React.createElement("span", {
    key: item,
    className: "liquid-glass rounded-full px-3 py-1 text-[11px] text-white/90 font-body"
  }, item))));
}
function Pricing({ t }) {
  return /*#__PURE__*/React.createElement("section", {
    id: "pricing",
    className: "relative w-full bg-black overflow-hidden"
  }, /*#__PURE__*/React.createElement("div", {
    className: "pointer-events-none absolute inset-0 z-0",
    style: { background: "radial-gradient(ellipse 60% 50% at 82% 100%, rgba(127,194,224,0.11), transparent 62%)" },
    "aria-hidden": "true"
  }), /*#__PURE__*/React.createElement("div", {
    className: "relative z-10 px-8 md:px-16 lg:px-20 py-28"
  }, /*#__PURE__*/React.createElement(motion.div, rise(0), /*#__PURE__*/React.createElement(Kicker, null, t("prc.kicker")), /*#__PURE__*/React.createElement(Display, null, t("prc.h2a"), /*#__PURE__*/React.createElement("br", null), t("prc.h2b"))), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-1 md:grid-cols-3 gap-6 mt-16 items-stretch"
  }, /*#__PURE__*/React.createElement(motion.div, rise(0), /*#__PURE__*/React.createElement(Tier, {
    title: t("prc.t1Title"), price: t("prc.t1Price"), desc: t("prc.t1Desc"),
    items: [t("prc.t1a"), t("prc.t1b"), t("prc.t1c")]
  })), /*#__PURE__*/React.createElement(motion.div, rise(0.08), /*#__PURE__*/React.createElement(Tier, {
    featured: true, badge: t("prc.t2Badge"), title: t("prc.t2Title"), price: t("prc.t2Price"), desc: t("prc.t2Desc"),
    items: [t("prc.t2a"), t("prc.t2b"), t("prc.t2c"), t("prc.t2d")]
  })), /*#__PURE__*/React.createElement(motion.div, rise(0.16), /*#__PURE__*/React.createElement(Tier, {
    title: t("prc.t3Title"), price: t("prc.t3Price"), desc: t("prc.t3Desc"),
    items: [t("prc.t3a"), t("prc.t3b"), t("prc.t3c")]
  }))), /*#__PURE__*/React.createElement(motion.p, _extends({}, rise(0.1), {
    className: "mt-8 text-sm text-white/60 font-body font-light"
  }), t("prc.note"))));
}

/* ------------------------------------------------------------ PhoneCanvas
   A transparent, wireframed iPhone-style device on the Contact section,
   with a glass notification card that slides in from the top edge on a
   loop — styled entirely from the site's own signal-blue accent. */

function PhoneCanvas() {
  const canvasRef = useRef(null);
  const pointerRef = useRef({ x: 0, y: 0 });
  useEffect(() => {
    let raf = null;
    let cancelled = false;
    const onMove = e => {
      pointerRef.current = { x: e.clientX / window.innerWidth - 0.5, y: e.clientY / window.innerHeight - 0.5 };
    };
    window.addEventListener("pointermove", onMove);
    const reduced = reducedMotion();
    const roundedRect = (w, h, r) => {
      const s = new window.THREE.Shape();
      const x = -w / 2, y = -h / 2;
      s.moveTo(x, y + r);
      s.lineTo(x, y + h - r);
      s.quadraticCurveTo(x, y + h, x + r, y + h);
      s.lineTo(x + w - r, y + h);
      s.quadraticCurveTo(x + w, y + h, x + w, y + h - r);
      s.lineTo(x + w, y + r);
      s.quadraticCurveTo(x + w, y, x + w - r, y);
      s.lineTo(x + r, y);
      s.quadraticCurveTo(x, y, x, y + r);
      return s;
    };
    const init = attempt => {
      if (cancelled) return;
      if (!window.THREE) {
        if (attempt < 20) setTimeout(() => init(attempt + 1), 150);
        return;
      }
      const canvas = canvasRef.current;
      if (!canvas) return;
      const THREE = window.THREE;
      const rect = canvas.parentElement.getBoundingClientRect();
      const w = rect.width, h = rect.height;
      const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      renderer.setSize(w, h, false);

      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(30, w / h, 0.1, 100);
      camera.position.set(0, 0, 6.6);

      const phone = new THREE.Group();
      scene.add(phone);

      const bodyShape = roundedRect(1.5, 3.05, 0.32);
      const bodyGeo = new THREE.ExtrudeGeometry(bodyShape, { depth: 0.16, bevelEnabled: true, bevelThickness: 0.02, bevelSize: 0.02, bevelSegments: 3, curveSegments: 16 });
      bodyGeo.center();
      const bodyMat = new THREE.MeshStandardMaterial({ color: 0x0b0d10, transparent: true, opacity: 0.12, metalness: 0.4, roughness: 0.2 });
      const body = new THREE.Mesh(bodyGeo, bodyMat);
      phone.add(body);
      body.add(new THREE.LineSegments(new THREE.EdgesGeometry(bodyGeo, 30), new THREE.LineBasicMaterial({ color: 0x7fc2e0, transparent: true, opacity: 0.55 })));

      const screenShape = roundedRect(1.34, 2.86, 0.26);
      const screenGeo = new THREE.ShapeGeometry(screenShape);
      const screenMat = new THREE.MeshStandardMaterial({ color: 0x7fc2e0, transparent: true, opacity: 0.045, side: THREE.DoubleSide });
      const screen = new THREE.Mesh(screenGeo, screenMat);
      screen.position.z = 0.09;
      phone.add(screen);

      const islandGeo = new THREE.ShapeGeometry(roundedRect(0.34, 0.1, 0.05));
      const islandMat = new THREE.MeshStandardMaterial({ color: 0x000000, transparent: true, opacity: 0.55 });
      const island = new THREE.Mesh(islandGeo, islandMat);
      island.position.set(0, 1.32, 0.1);
      phone.add(island);

      const btnMat = new THREE.MeshStandardMaterial({ color: 0x7fc2e0, transparent: true, opacity: 0.3 });
      const volUp = new THREE.Mesh(new THREE.BoxGeometry(0.03, 0.28, 0.05), btnMat);
      volUp.position.set(-0.77, 0.75, 0);
      phone.add(volUp);
      const volDown = new THREE.Mesh(new THREE.BoxGeometry(0.03, 0.28, 0.05), btnMat);
      volDown.position.set(-0.77, 0.35, 0);
      phone.add(volDown);
      const power = new THREE.Mesh(new THREE.BoxGeometry(0.03, 0.42, 0.05), btnMat);
      power.position.set(0.77, 0.55, 0);
      phone.add(power);

      const notif = new THREE.Group();
      const cardGeo = new THREE.BoxGeometry(1.08, 0.34, 0.02);
      const cardMat = new THREE.MeshStandardMaterial({ color: 0xffffff, transparent: true, opacity: 0.07, metalness: 0.1, roughness: 0.3 });
      const card = new THREE.Mesh(cardGeo, cardMat);
      notif.add(card);
      const cardEdges = new THREE.LineSegments(new THREE.EdgesGeometry(cardGeo), new THREE.LineBasicMaterial({ color: 0x7fc2e0, transparent: true, opacity: 0.7 }));
      card.add(cardEdges);
      const dot = new THREE.Mesh(new THREE.CircleGeometry(0.075, 20), new THREE.MeshBasicMaterial({ color: 0xe2695a, transparent: true, opacity: 0.9 }));
      dot.position.set(-0.38, 0, 0.02);
      notif.add(dot);
      const bar1 = new THREE.Mesh(new THREE.PlaneGeometry(0.52, 0.045), new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.85 }));
      bar1.position.set(-0.02, 0.06, 0.02);
      notif.add(bar1);
      const bar2 = new THREE.Mesh(new THREE.PlaneGeometry(0.38, 0.035), new THREE.MeshBasicMaterial({ color: 0x93aec2, transparent: true, opacity: 0.6 }));
      bar2.position.set(-0.09, -0.06, 0.02);
      notif.add(bar2);
      notif.position.set(0, 1.05, 0.14);
      phone.add(notif);

      scene.add(new THREE.AmbientLight(0x22303a, 1.6));
      const key = new THREE.DirectionalLight(0x7fc2e0, 1.2);
      key.position.set(2, 3, 4);
      scene.add(key);
      const fill = new THREE.PointLight(0x7fc2e0, 2, 12);
      fill.position.set(-2, -1, 3);
      scene.add(fill);

      const T = 4200;
      const start0 = performance.now();
      const animate = now => {
        const c = (now - start0) % T / T;
        let y, op;
        if (c < 0.18) { y = 1.75; op = 0; }
        else if (c < 0.36) { const p = (c - 0.18) / 0.18; const e = 1 - Math.pow(1 - p, 3); y = 1.75 - e * 0.7; op = e; }
        else if (c < 0.72) { y = 1.05 + Math.sin(now * 0.0025) * 0.02; op = 1; }
        else if (c < 0.86) { const p = (c - 0.72) / 0.14; y = 1.05; op = 1 - p; }
        else { y = 1.75; op = 0; }
        notif.position.y = y;
        card.material.opacity = 0.07 * op;
        cardEdges.material.opacity = 0.7 * op;
        dot.material.opacity = 0.9 * op;
        bar1.material.opacity = 0.85 * op;
        bar2.material.opacity = 0.6 * op;

        if (!reduced) {
          phone.rotation.y = Math.sin(now * 0.0006) * 0.22;
          const p = pointerRef.current;
          phone.rotation.x += (-p.y * 0.15 - phone.rotation.x) * 0.05;
        }
        renderer.render(scene, camera);
        raf = requestAnimationFrame(animate);
      };
      raf = requestAnimationFrame(animate);
    };
    init(0);
    return () => {
      cancelled = true;
      window.removeEventListener("pointermove", onMove);
      if (raf) cancelAnimationFrame(raf);
    };
  }, []);
  return /*#__PURE__*/React.createElement("canvas", {
    ref: canvasRef,
    "aria-hidden": "true",
    className: "block w-full",
    style: { maxWidth: 260, height: "min(60vw,340px)" }
  });
}

/* ----------------------------------------------------------- contact */

function Contact({ t }) {
  const rows = [["Telegram", "@floydark", "https://t.me/floydark"], ["GitHub", "Wo1and29/woland-guard", "https://github.com/Wo1and29/woland-guard"]];
  return /*#__PURE__*/React.createElement("section", {
    id: "contact",
    className: "relative w-full bg-black overflow-hidden"
  }, /*#__PURE__*/React.createElement("div", {
    className: "pointer-events-none absolute inset-0 z-0",
    style: { background: "radial-gradient(ellipse 65% 60% at 50% 15%, rgba(127,194,224,0.14), transparent 62%)" },
    "aria-hidden": "true"
  }), /*#__PURE__*/React.createElement("div", {
    className: "relative z-10 px-8 md:px-16 lg:px-20 py-28"
  }, /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-1 md:grid-cols-3 gap-12 items-center"
  }, /*#__PURE__*/React.createElement(motion.div, rise(0), /*#__PURE__*/React.createElement(Kicker, null, t("ct.kicker")), /*#__PURE__*/React.createElement(Display, {
    className: "lg:text-[5rem]"
  }, t("ct.h2a"), /*#__PURE__*/React.createElement("br", null), t("ct.h2b")), /*#__PURE__*/React.createElement("p", {
    className: "mt-6 text-sm md:text-base text-white/85 font-body font-light leading-snug max-w-[44ch]"
  }, t("ct.lede"))), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-center"
  }, /*#__PURE__*/React.createElement(PhoneCanvas, null)), /*#__PURE__*/React.createElement(motion.div, _extends({}, rise(0.1), {
    className: "flex flex-col gap-3"
  }), rows.map(([label, value, href]) => /*#__PURE__*/React.createElement("a", {
    key: label, href: href, target: "_blank", rel: "noopener",
    className: "liquid-glass rounded-[1.25rem] px-6 py-5 flex items-center justify-between gap-4"
  }, /*#__PURE__*/React.createElement("span", {
    className: "min-w-0"
  }, /*#__PURE__*/React.createElement("span", {
    className: "block font-mono text-[10px] text-white/50 uppercase tracking-[0.14em]"
  }, label), /*#__PURE__*/React.createElement("span", {
    className: "block font-body font-semibold not-italic text-white text-2xl md:text-3xl tracking-[-1px] leading-tight break-all mt-0.5"
  }, value)), /*#__PURE__*/React.createElement(ArrowUpRight, { className: "h-6 w-6 text-signal shrink-0" })))))));
}
function Footer({ t }) {
  return /*#__PURE__*/React.createElement("footer", {
    className: "relative w-full bg-black px-8 md:px-16 lg:px-20 py-10 border-t border-white/10"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap items-center justify-between gap-4 text-xs text-white/45 font-body"
  }, /*#__PURE__*/React.createElement("span", null, "\xA9 2026 Dr. Woland"), /*#__PURE__*/React.createElement("span", null, t("ft.license"), " ", /*#__PURE__*/React.createElement("a", {
    className: "underline underline-offset-4 hover:text-signal",
    href: "https://github.com/Wo1and29/woland-guard/blob/master/LICENSE",
    target: "_blank", rel: "noopener"
  }, "AGPL-3.0-or-later"))));
}

/* --------------------------------------------------------------- app */

function App() {
  const { lang, setLang, t } = useT();
  return /*#__PURE__*/React.createElement(MotionConfig, { reducedMotion: "user" }, /*#__PURE__*/React.createElement("div", {
    className: "bg-black"
  }, /*#__PURE__*/React.createElement(Navbar, { lang: lang, setLang: setLang, t: t }), /*#__PURE__*/React.createElement(Hero, { t: t }), /*#__PURE__*/React.createElement(NetworkSection, { t: t }), /*#__PURE__*/React.createElement(Services, { t: t }), /*#__PURE__*/React.createElement(Project, { lang: lang, t: t }), /*#__PURE__*/React.createElement(Pricing, { t: t }), /*#__PURE__*/React.createElement(Contact, { t: t }), /*#__PURE__*/React.createElement(Footer, { t: t })));
}
ReactDOM.createRoot(document.getElementById("root")).render(/*#__PURE__*/React.createElement(App, null));
