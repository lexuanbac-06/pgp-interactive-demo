import { useEffect, useMemo, useState, type FormEvent } from "react";
import type { ReactNode } from "react";
import {
  ArrowDownToLine,
  ArrowLeft,
  ArrowRight,
  Check,
  Clipboard,
  ClipboardCheck,
  FileKey2,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  Mail,
  MessageCircleWarning,
  Plus,
  RefreshCw,
  ShieldCheck,
  ShieldQuestion,
  UnlockKeyhole,
  Upload,
  UserRound,
  X,
} from "lucide-react";

type Identity = {
  name: string;
  fingerprint: string;
  bits?: number;
};

type User = {
  id: string;
  name: string;
  key: Identity | null;
};

type Step = {
  label: string;
  detail: string;
  value: string;
  status?: "success" | "failed" | "warning";
};

type StepAdvance = {
  step: Step;
  done: boolean;
};

type Notice = {
  kind: "success" | "error" | "info";
  text: string;
};

type SignatureResult = {
  status: "valid" | "modified" | "unknown" | "unsigned";
  message: string;
};

type AppState = {
  users: User[];
  selected_user_id: string | null;
  contacts: Identity[];
};

type AppTab = "send" | "receive" | "keyring";

async function api<T>(path: string, body?: object): Promise<T> {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error("Máy chủ trả về dữ liệu không đọc được.");
  }

  if (!response.ok) {
    const error =
      typeof payload === "object" && payload !== null && "error" in payload
        ? String(payload.error)
        : "Yêu cầu không thành công.";
    throw new Error(error);
  }

  return payload as T;
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Đã xảy ra lỗi không xác định.";
}

function StatusMessage({ notice }: { notice?: Notice }) {
  if (!notice) return null;
  return (
    <div className={`notice-message ${notice.kind}`} role={notice.kind === "error" ? "alert" : "status"}>
      {notice.kind === "success" ? <Check size={16} /> : <MessageCircleWarning size={16} />}
      <span>{notice.text}</span>
    </div>
  );
}

function SectionHeading({
  icon,
  eyebrow,
  title,
  description,
  trailing,
}: {
  icon: ReactNode;
  eyebrow: string;
  title: string;
  description: string;
  trailing?: ReactNode;
}) {
  return (
    <div className="section-heading">
      <div className="section-icon">{icon}</div>
      <div className="section-heading-copy">
        <span className="eyebrow">{eyebrow}</span>
        <h2>{title}</h2>
        <p>{description}</p>
      </div>
      {trailing}
    </div>
  );
}

function Stepper({
  steps,
  onComplete,
  onCopyError,
  successMessage,
  onAdvance,
  resetKey,
  totalSteps,
  initialDone,
}: {
  steps: Step[];
  onComplete: () => void;
  onCopyError: () => void;
  successMessage: string;
  onAdvance?: () => Promise<StepAdvance | undefined>;
  resetKey?: string | null;
  totalSteps?: number;
  initialDone?: boolean;
}) {
  const [index, setIndex] = useState(0);
  const [complete, setComplete] = useState(false);
  const [copied, setCopied] = useState(false);
  const [advancing, setAdvancing] = useState(false);
  const [terminal, setTerminal] = useState(initialDone ?? !onAdvance);
  const step = steps[index];
  const failedStep = steps.find((item) => item.status === "failed");
  const warningStep = steps.find((item) => item.status === "warning");

  useEffect(() => {
    setIndex(0);
    setComplete(false);
    setCopied(false);
    setTerminal(initialDone ?? !onAdvance);
  }, [resetKey]);

  async function copyValue() {
    try {
      await navigator.clipboard.writeText(step.value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      onCopyError();
    }
  }

  async function next() {
    if (advancing) return;
    if (complete) {
      onComplete();
      return;
    }
    if (index < steps.length - 1) {
      setIndex((current) => current + 1);
      return;
    }
    if (onAdvance && !terminal) {
      setAdvancing(true);
      try {
        const result = await onAdvance();
        if (result) {
          setIndex((current) => current + 1);
          setTerminal(result.done);
        }
      } finally {
        setAdvancing(false);
      }
      return;
    }
    setComplete(true);
  }

  function previous() {
    if (index > 0) setIndex((current) => current - 1);
  }

  if (!step) return null;

  return (
    <div className="stepper" aria-live="polite">
      {complete ? (
        <div className={`step-success ${failedStep ? "failed" : warningStep ? "warning" : ""}`} role="status">
          <div className="step-success-icon">{failedStep ? <MessageCircleWarning size={22} /> : warningStep ? <ShieldQuestion size={22} /> : <Check size={22} />}</div>
          <span className="eyebrow">{failedStep ? "ĐÃ PHÁT HIỆN LỖI" : warningStep ? "CHƯA THỂ XÁC MINH ĐẦY ĐỦ" : "QUY TRÌNH HOÀN TẤT"}</span>
          <h3>{failedStep ? "Phát hiện dữ liệu không hợp lệ" : warningStep ? "Cần thêm khóa công khai" : "Thành công"}</h3>
          <p>{failedStep ? `${failedStep.label}: ${failedStep.value}` : warningStep ? warningStep.value : successMessage}</p>
        </div>
      ) : (
        <>
          <div className="stepper-topline">
            <span className="step-counter">BƯỚC {index + 1}</span>
            <span className="step-total">{index + 1} / {totalSteps || steps.length}</span>
          </div>
          <div className="progress-track" aria-label={`Bước ${index + 1} trên ${totalSteps || steps.length}`}>
            <span style={{ width: `${((index + 1) / (totalSteps || steps.length)) * 100}%` }} />
          </div>
          <div className={`step-card ${step.status === "failed" ? "failed" : step.status === "warning" ? "warning" : ""}`}>
            <div className="step-card-number">{String(index + 1).padStart(2, "0")}</div>
            <div className="step-card-content">
              <h3>{step.label}{step.status === "failed" && <span className="step-status failed">Phát hiện lỗi</span>}{step.status === "warning" && <span className="step-status warning">Chưa xác minh</span>}</h3>
              <p>{step.detail}</p>
              <div className={`step-result ${step.label.includes("AES-256") ? "secret" : ""} ${step.status === "failed" ? "failed" : step.status === "warning" ? "warning" : ""}`}>
                <code>{step.value}</code>
                <button type="button" className="icon-button copy-button" onClick={() => void copyValue()} aria-label="Sao chép kết quả bước">
                  {copied ? <ClipboardCheck size={16} /> : <Clipboard size={16} />}
                  <span>{copied ? "Đã chép" : "Sao chép"}</span>
                </button>
              </div>
            </div>
          </div>
        </>
      )}
      <div className="stepper-controls">
        {complete ? (
          <button type="button" className="button button-quiet" onClick={() => setComplete(false)}>
            <ArrowLeft size={16} /> Bước cuối
          </button>
        ) : (
          <button type="button" className="button button-quiet" onClick={previous} disabled={index === 0}>
            <ArrowLeft size={16} /> Quay lại
          </button>
        )}
        {!complete && <span className="step-dots" aria-hidden="true">
          {steps.map((_, dotIndex) => (
            <span key={dotIndex} className={dotIndex === index ? "active" : dotIndex < index ? "done" : ""} />
          ))}
        </span>}
        <button type="button" className="button button-primary" onClick={() => void next()} disabled={advancing}>
          {advancing ? <><span className="spinner" /> Đang xử lý…</> : complete ? <>Tiếp theo <ArrowRight size={16} /></> : index === steps.length - 1 && terminal ? <>Xem kết quả <ArrowRight size={16} /></> : <>Tiếp theo <ArrowRight size={16} /></>}
        </button>
      </div>
    </div>
  );
}

function Modal({
  title,
  description,
  onClose,
  children,
}: {
  title: string;
  description: string;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <div className="modal-backdrop" onMouseDown={(event) => {
      if (event.target === event.currentTarget) onClose();
    }}>
      <section className="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
        <button type="button" className="icon-button modal-close" onClick={onClose} aria-label="Đóng">
          <X size={18} />
        </button>
        <div className="modal-mark"><KeyRound size={20} /></div>
        <span className="eyebrow">PGP LAB</span>
        <h2 id="modal-title">{title}</h2>
        <p className="modal-description">{description}</p>
        {children}
      </section>
    </div>
  );
}

export default function App() {
  const [users, setUsers] = useState<User[]>([]);
  const [contacts, setContacts] = useState<Identity[]>([]);
  const [activeId, setActiveId] = useState("");
  const [loading, setLoading] = useState(true);
  const [pageError, setPageError] = useState("");
  const [activeTab, setActiveTab] = useState<AppTab>("send");
  const [sendFlowActive, setSendFlowActive] = useState(false);
  const [receiveFlowActive, setReceiveFlowActive] = useState(false);

  const [message, setMessage] = useState("");
  const [encrypt, setEncrypt] = useState(true);
  const [sign, setSign] = useState(true);
  const [recipientFingerprint, setRecipientFingerprint] = useState("");
  const [signerId, setSignerId] = useState("");
  const [signerPassphrase, setSignerPassphrase] = useState("");
  const [receiverId, setReceiverId] = useState("");
  const [receiverPassphrase, setReceiverPassphrase] = useState("");
  const [packageInput, setPackageInput] = useState("");
  const [packageOutput, setPackageOutput] = useState("");

  const [sendSteps, setSendSteps] = useState<Step[]>([]);
  const [sendSessionId, setSendSessionId] = useState<string | null>(null);
  const [sendTotalSteps, setSendTotalSteps] = useState(5);
  const [sendRunId, setSendRunId] = useState(0);
  const [receiveSteps, setReceiveSteps] = useState<Step[]>([]);
  const [receiveSessionId, setReceiveSessionId] = useState<string | null>(null);
  const [receiveTotalSteps, setReceiveTotalSteps] = useState(4);
  const [receiveRunId, setReceiveRunId] = useState(0);
  const [sendComplete, setSendComplete] = useState(false);
  const [receiveComplete, setReceiveComplete] = useState(false);
  const [openedMessage, setOpenedMessage] = useState("");
  const [signatureResult, setSignatureResult] = useState<SignatureResult | null>(null);

  const [notices, setNotices] = useState<Record<string, Notice | undefined>>({});
  const [keyModalOpen, setKeyModalOpen] = useState(false);
  const [userModalOpen, setUserModalOpen] = useState(false);
  const [keyPassphrase, setKeyPassphrase] = useState("");
  const [keyBits, setKeyBits] = useState(2048);
  const [newUserName, setNewUserName] = useState("");
  const [publicKeyInput, setPublicKeyInput] = useState("");
  const [busy, setBusy] = useState("");

  const activeUser = users.find((user) => user.id === activeId);
  const recipients = useMemo(() => {
    const fromUsers = users
      .filter((user) => user.id !== activeId && user.key)
      .map((user) => ({ ...user.key!, name: user.name }));
    const combined = [...fromUsers];
    for (const contact of contacts) {
      if (!combined.some((item) => item.fingerprint === contact.fingerprint)) combined.push(contact);
    }
    return combined;
  }, [users, activeId, contacts]);
  const signers = users.filter((user) => user.key);
  const receiverChoices = users;

  function setNotice(key: string, notice?: Notice) {
    setNotices((current) => ({ ...current, [key]: notice }));
  }

  async function refresh(selectedId?: string) {
    const query = selectedId ? `?user_id=${encodeURIComponent(selectedId)}` : "";
    const result = await api<AppState>(`/api/state${query}`);
    const selected = selectedId || result.selected_user_id || result.users[0]?.id || "";
    setUsers(result.users);
    setContacts(result.contacts || []);
    setActiveId(selected);
    return selected;
  }

  useEffect(() => {
    void refresh()
      .catch((error: unknown) => setPageError(getErrorMessage(error)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!recipients.some((item) => item.fingerprint === recipientFingerprint)) {
      setRecipientFingerprint(recipients[0]?.fingerprint || "");
    }
  }, [recipients, recipientFingerprint]);

  useEffect(() => {
    if (!signers.some((user) => user.id === signerId)) {
      setSignerId(signers.find((user) => user.id === activeId)?.id || signers[0]?.id || "");
    }
  }, [signers, signerId, activeId]);

  useEffect(() => {
    if (!receiverChoices.some((user) => user.id === receiverId)) setReceiverId(activeId);
  }, [receiverChoices, receiverId, activeId]);

  async function selectUser(userId: string) {
    setNotices({});
    setSignerPassphrase("");
    setReceiverPassphrase("");
    setSendSteps([]);
    setSendSessionId(null);
    setSendRunId((current) => current + 1);
    setReceiveSteps([]);
    setReceiveSessionId(null);
    setReceiveRunId((current) => current + 1);
    setSendFlowActive(false);
    setReceiveFlowActive(false);
    setSendComplete(false);
    setReceiveComplete(false);
    setOpenedMessage("");
    setSignatureResult(null);
    try {
      await refresh(userId);
    } catch (error) {
      setNotice("key", { kind: "error", text: getErrorMessage(error) });
    }
  }

  async function copy(text: string, success: string, noticeKey: string) {
    try {
      await navigator.clipboard.writeText(text);
      setNotice(noticeKey, { kind: "success", text: success });
    } catch {
      setNotice(noticeKey, { kind: "info", text: "Clipboard bị chặn. Hãy sao chép nội dung trong ô văn bản." });
    }
  }

  async function exportPublicKey() {
    try {
      const result = await api<{ armored: string }>("/api/keys/export", { user_id: activeId });
      setPublicKeyInput(result.armored);
      await copy(result.armored, "Đã export và sao chép khóa công khai.", "key");
    } catch (error) {
      setNotice("key", { kind: "error", text: getErrorMessage(error) });
    }
  }

  async function importPublicKey() {
    setNotice("key", undefined);
    try {
      const result = await api<{ key: Identity }>("/api/keys/import", {
        user_id: activeId,
        armored: publicKeyInput,
      });
      setPublicKeyInput("");
      await refresh(activeId);
      setNotice("key", {
        kind: "success",
        text: `Đã import khóa của ${result.key.name}. Fingerprint: ${result.key.fingerprint}`,
      });
    } catch (error) {
      setNotice("key", { kind: "error", text: getErrorMessage(error) });
    }
  }

  async function generateKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!activeId) return;
    if (activeUser?.key && !window.confirm("Tạo khóa mới sẽ thay thế khóa cũ. Gói tin đã mã hóa cho khóa cũ sẽ không thể giải mã bằng khóa mới. Tiếp tục?")) return;
    setBusy("key");
    setNotice("modal", undefined);
    try {
      const result = await api<{ fingerprint: string; bits: number }>("/api/keys/generate", {
        user_id: activeId,
        passphrase: keyPassphrase,
        bits: keyBits,
      });
      setKeyModalOpen(false);
      setKeyPassphrase("");
      await refresh(activeId);
      setNotice("key", {
        kind: "success",
        text: `Đã tạo khóa RSA ${result.bits} bit. Fingerprint: ${result.fingerprint}`,
      });
    } catch (error) {
      setNotice("modal", { kind: "error", text: getErrorMessage(error) });
    } finally {
      setBusy("");
    }
  }

  async function addUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("user");
    try {
      const result = await api<{ user: { id: string } }>("/api/users", { name: newUserName.trim() });
      setUserModalOpen(false);
      setNewUserName("");
      await refresh(result.user.id);
    } catch (error) {
      setNotice("userModal", { kind: "error", text: getErrorMessage(error) });
    } finally {
      setBusy("");
    }
  }

  async function compose() {
    if (!message.trim()) {
      setNotice("compose", { kind: "error", text: "Hãy nhập nội dung trước khi tạo gói tin." });
      return;
    }
    setBusy("compose");
    setNotice("compose", undefined);
    setSendSteps([]);
    setSendComplete(false);
    setSendSessionId(null);
    setSendRunId((current) => current + 1);
    setSendFlowActive(false);
    setPackageOutput("");
    try {
      const result = await api<{
        session_id: string | null;
        step: Step;
        done: boolean;
        result: { armored: string } | null;
        total_steps: number;
      }>("/api/messages/create", {
        sender_id: activeId,
        message,
        encrypt,
        recipient_fingerprint: recipientFingerprint,
        sign,
        signer_id: signerId,
        signer_passphrase: signerPassphrase,
      });
      setPackageOutput(result.result?.armored || "");
      if (result.result?.armored) setPackageInput(result.result.armored);
      setSendSessionId(result.session_id);
      setSendTotalSteps(result.total_steps);
      setSendSteps([result.step]);
      setSendFlowActive(true);
      setSignerPassphrase("");
      const recipient = users.find((user) => user.key?.fingerprint === recipientFingerprint);
      if (recipient) setReceiverId(recipient.id);
      setNotice("compose", undefined);
      setActiveTab("send");
      window.requestAnimationFrame(() => {
        document.getElementById("panel-send")?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    } catch (error) {
      setNotice("compose", { kind: "error", text: getErrorMessage(error) });
    } finally {
      setBusy("");
    }
  }

  async function advanceSend(): Promise<StepAdvance | undefined> {
    if (!sendSessionId) return undefined;
    try {
      const result = await api<{
        session_id: string | null;
        step: Step;
        done: boolean;
        result: { armored: string } | null;
        total_steps: number;
      }>("/api/messages/create/next", { session_id: sendSessionId });
      setSendSteps((current) => [...current, result.step]);
      setSendSessionId(result.session_id);
      if (result.result?.armored) {
        setPackageOutput(result.result.armored);
        setPackageInput(result.result.armored);
      }
      return { step: result.step, done: result.done };
    } catch (error) {
      setNotice("compose", { kind: "error", text: getErrorMessage(error) });
      return undefined;
    }
  }

  async function openMessage() {
    setBusy("open");
    setNotice("open", undefined);
    setReceiveSteps([]);
    setReceiveSessionId(null);
    setReceiveRunId((current) => current + 1);
    setReceiveComplete(false);
    setReceiveFlowActive(false);
    setOpenedMessage("");
    setSignatureResult(null);
    try {
      const result = await api<{
        session_id: string | null;
        step: Step;
        done: boolean;
        result: { message: string; encrypted: boolean; signature: SignatureResult } | null;
        total_steps: number;
      }>("/api/messages/open", {
        user_id: receiverId,
        armored: packageInput,
        passphrase: receiverPassphrase,
      });
      setOpenedMessage(result.result?.message || "");
      setSignatureResult(result.result?.signature || null);
      setReceiveSessionId(result.session_id);
      setReceiveTotalSteps(result.total_steps);
      setReceiveSteps([result.step]);
      setReceiveFlowActive(true);
      setReceiverPassphrase("");
      setNotice("open", undefined);
      window.requestAnimationFrame(() => {
        document.getElementById("panel-receive")?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    } catch (error) {
      setNotice("open", { kind: "error", text: getErrorMessage(error) });
    } finally {
      setBusy("");
    }
  }

  async function advanceReceive(): Promise<StepAdvance | undefined> {
    if (!receiveSessionId) return undefined;
    try {
      const result = await api<{
        session_id: string | null;
        step: Step;
        done: boolean;
        result: { message: string; encrypted: boolean; signature: SignatureResult } | null;
        total_steps: number;
      }>("/api/messages/open/next", { session_id: receiveSessionId });
      setReceiveSteps((current) => [...current, result.step]);
      setReceiveSessionId(result.session_id);
      if (result.result) {
        setOpenedMessage(result.result.message);
        setSignatureResult(result.result.signature);
      }
      return { step: result.step, done: result.done };
    } catch (error) {
      setNotice("open", { kind: "error", text: getErrorMessage(error) });
      return undefined;
    }
  }

  if (loading) {
    return <main className="loading-screen"><div className="loading-mark"><LockKeyhole size={24} /></div><p>Đang mở phòng thực hành…</p></main>;
  }

  if (pageError) {
    return (
      <main className="loading-screen">
        <div className="error-panel"><ShieldQuestion size={26} /><h1>Không thể kết nối</h1><p>{pageError}</p><button className="button button-primary" onClick={() => window.location.reload()}><RefreshCw size={16} /> Thử lại</button></div>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#" aria-label="PGP Lab trang chủ">
          <span className="brand-symbol"><LockKeyhole size={21} /></span>
          <span><strong>PGP<span>Lab</span></strong><small>CRYPTOGRAPHY PLAYGROUND</small></span>
        </a>
        <div className="topbar-right">
          <span className="local-indicator"><span /> Đang chạy cục bộ</span>
          <span className="version-badge"><ShieldCheck size={14} /> DEMO HỌC TẬP</span>
        </div>
      </header>

      <section className="hero">
        <div className="hero-copy">
          <div className="hero-kicker"><span className="hero-kicker-line" /> PHÒNG THỰC HÀNH MẬT MÃ</div>
          <h1>Hiểu cách thông điệp<br /><span>được bảo vệ.</span></h1>
          <p>Khám phá chữ ký số và mã hóa lai qua một quy trình tương tác — từng bước một.</p>
        </div>
        <div className="hero-art" aria-hidden="true">
          <div className="orbit orbit-one" /><div className="orbit orbit-two" />
          <div className="hero-lock"><LockKeyhole size={43} strokeWidth={1.5} /></div>
          <span className="orbit-chip chip-one"><Fingerprint size={16} /></span>
          <span className="orbit-chip chip-two"><ShieldCheck size={16} /></span>
          <span className="orbit-chip chip-three"><KeyRound size={16} /></span>
        </div>
      </section>

      <div className="security-note">
        <ShieldCheck size={17} />
        <p><strong>Mô phỏng an toàn để học tập.</strong> Gói tin dùng RSA-PSS, RSA-OAEP, AES-256-GCM và SHA-256, nhưng định dạng không tương thích OpenPGP — không dùng để bảo vệ dữ liệu thật.</p>
      </div>

      <nav className="user-switcher" aria-label="Danh tính">
        <div className="user-switcher-label">DANH TÍNH</div>
        <div className="user-tabs">
          {users.map((user) => (
            <button key={user.id} type="button" className={`user-tab ${activeId === user.id ? "active" : ""}`} onClick={() => void selectUser(user.id)}>
              <span className="avatar">{user.name.slice(0, 1).toUpperCase()}</span>
              <span>{user.name}</span>
              {user.key && <span className="user-key-dot" title="Đã có khóa" />}
            </button>
          ))}
        </div>
        <button type="button" className="add-user-button" onClick={() => { setNotice("userModal", undefined); setUserModalOpen(true); }}>
          <Plus size={16} /> Thêm danh tính
        </button>
      </nav>

      <nav className="app-tabs" role="tablist" aria-label="Khu vực ứng dụng">
        <button type="button" role="tab" id="tab-send" aria-selected={activeTab === "send"} aria-controls="panel-send" className={`app-tab ${activeTab === "send" ? "active" : ""}`} onClick={() => setActiveTab("send")}>
          <Mail size={17} /><span>Gửi</span><small>Tạo và ký gói tin</small>
        </button>
        <button type="button" role="tab" id="tab-receive" aria-selected={activeTab === "receive"} aria-controls="panel-receive" className={`app-tab ${activeTab === "receive" ? "active" : ""}`} onClick={() => setActiveTab("receive")}>
          <UnlockKeyhole size={17} /><span>Nhận</span><small>Giải mã và xác minh</small>
        </button>
        <button type="button" role="tab" id="tab-keyring" aria-selected={activeTab === "keyring"} aria-controls="panel-keyring" className={`app-tab ${activeTab === "keyring" ? "active" : ""}`} onClick={() => setActiveTab("keyring")}>
          <KeyRound size={17} /><span>Keyring</span><small>Quản lý khóa</small>
        </button>
      </nav>

      <main className="workspace" data-active-tab={activeTab}>
        <div className="primary-column">
          <section id="panel-send" role="tabpanel" aria-labelledby="tab-send" hidden={activeTab !== "send"} className={`panel compose-panel ${sendFlowActive ? "flow-panel" : ""}`}>
            <SectionHeading
              icon={<Mail size={19} />}
              eyebrow={sendFlowActive ? "QUY TRÌNH MẬT MÃ · PHÍA GỬI" : "01 · TẠO THÔNG ĐIỆP"}
              title={sendFlowActive ? "Đang tạo gói tin" : "Soạn & gửi"}
              description={sendFlowActive ? `Theo dõi lần lượt các bước xử lý${activeUser ? ` · ${activeUser.name}` : ""}.` : "Viết nội dung, ký bằng khóa riêng và mã hóa cho người nhận."}
              trailing={!sendFlowActive && activeUser && <span className="acting-as"><UserRound size={14} /> {activeUser.name}</span>}
            />
            <div className="panel-content">
              {sendFlowActive && sendSteps.length > 0 ? (
                <Stepper
                  steps={sendSteps}
                  onAdvance={advanceSend}
                  resetKey={String(sendRunId)}
                  totalSteps={sendTotalSteps}
                  initialDone={sendSessionId === null}
                  successMessage="Gói tin đã được tạo thành công và sẵn sàng để gửi."
                  onComplete={() => {
                    setSendFlowActive(false);
                    const failedStep = sendSteps.find((step) => step.status === "failed");
                    setSendComplete(Boolean(packageOutput) && !failedStep);
                    setNotice("compose", failedStep
                      ? { kind: "error", text: `Phát hiện lỗi tại bước “${failedStep.label}”. ${failedStep.value}` }
                      : { kind: "success", text: "Đã tạo gói tin thành công. Bạn có thể sao chép và gửi cho người nhận." });
                  }}
                  onCopyError={() => setNotice("compose", { kind: "info", text: "Clipboard bị chặn. Hãy chọn giá trị để sao chép." })}
                />
              ) : (
                <>
              {sendComplete && (
                <div className="package-card returned-package">
                  <div className="package-heading"><div className="package-icon"><ShieldCheck size={17} /></div><div><strong>Gói tin đã sẵn sàng</strong><small>ASCII armor · có thể gửi cho người nhận</small></div></div>
                  <textarea className="armor-input" value={packageOutput} readOnly rows={5} aria-label="Gói tin ASCII armor" />
                  <button type="button" className="button button-outline" onClick={() => void copy(packageOutput, "Đã sao chép gói tin.", "compose")}><Clipboard size={16} /> Sao chép gói tin</button>
                </div>
              )}
              <label className="field-label" htmlFor="message">Nội dung tin nhắn</label>
              <textarea
                id="message"
                className="message-input"
                value={message}
                onChange={(event) => setMessage(event.target.value)}
                placeholder="Viết một thông điệp cần gửi…"
                rows={4}
              />
              <div className="form-grid">
                <div>
                  <label className="field-label" htmlFor="recipient">Người nhận</label>
                  <select id="recipient" value={recipientFingerprint} onChange={(event) => setRecipientFingerprint(event.target.value)}>
                    <option value="">Chọn khóa công khai người nhận</option>
                    {recipients.map((recipient) => <option key={recipient.fingerprint} value={recipient.fingerprint}>{recipient.name} · {recipient.fingerprint.slice(0, 15)}…</option>)}
                  </select>
                </div>
                <div>
                  <label className="field-label" htmlFor="signer">Người ký</label>
                  <select id="signer" value={signerId} onChange={(event) => setSignerId(event.target.value)}>
                    <option value="">Chọn khóa người ký</option>
                    {signers.map((signer) => <option key={signer.id} value={signer.id}>{signer.name} · khóa riêng</option>)}
                  </select>
                </div>
              </div>

              {sign && (
                <div className="field-block">
                  <label className="field-label" htmlFor="signer-passphrase">Passphrase khóa riêng người ký</label>
                  <div className="input-with-icon"><KeyRound size={16} /><input id="signer-passphrase" type="password" autoComplete="current-password" value={signerPassphrase} onChange={(event) => setSignerPassphrase(event.target.value)} placeholder="Dùng để mở khóa riêng cục bộ" /></div>
                </div>
              )}

              <div className="option-row">
                <label className={`option-card ${sign ? "selected" : ""}`}>
                  <input type="checkbox" checked={sign} onChange={(event) => setSign(event.target.checked)} />
                  <span className="option-icon"><Fingerprint size={17} /></span>
                  <span><strong>Ký số</strong><small>Xác minh người gửi</small></span>
                  <span className="toggle"><i /></span>
                </label>
                <label className={`option-card ${encrypt ? "selected" : ""}`}>
                  <input type="checkbox" checked={encrypt} onChange={(event) => setEncrypt(event.target.checked)} />
                  <span className="option-icon"><LockKeyhole size={17} /></span>
                  <span><strong>Mã hóa</strong><small>Chỉ người nhận đọc được</small></span>
                  <span className="toggle"><i /></span>
                </label>
              </div>

              <StatusMessage notice={notices.compose} />
              <button type="button" className="button button-primary send-button" onClick={() => void compose()} disabled={busy === "compose"}>
                {busy === "compose" ? <span className="spinner" /> : <ArrowRight size={17} />}
                {busy === "compose" ? "Đang tạo gói tin…" : "Tạo gói tin"}
              </button>

                </>
              )}
            </div>
          </section>

          <section id="panel-receive" role="tabpanel" aria-labelledby="tab-receive" hidden={activeTab !== "receive"} className={`panel receive-panel ${receiveFlowActive ? "flow-panel" : ""}`}>
            <SectionHeading
              icon={<UnlockKeyhole size={19} />}
              eyebrow={receiveFlowActive ? "QUY TRÌNH MẬT MÃ · PHÍA NHẬN" : "02 · NHẬN THÔNG ĐIỆP"}
              title={receiveFlowActive ? "Đang xử lý gói tin" : "Giải mã & xác minh"}
              description={receiveFlowActive ? `Theo dõi lần lượt các bước giải mã${users.find((user) => user.id === receiverId) ? ` · ${users.find((user) => user.id === receiverId)?.name}` : ""}.` : "Dán gói tin, chọn danh tính nhận và xác minh chữ ký."}
            />
            <div className="panel-content">
              {receiveFlowActive && receiveSteps.length > 0 ? (
                <Stepper
                  steps={receiveSteps}
                  onAdvance={advanceReceive}
                  resetKey={String(receiveRunId)}
                  totalSteps={receiveTotalSteps}
                  initialDone={receiveSessionId === null}
                  successMessage="Đã hoàn thành các bước nhận gói tin. Kết quả giải mã và xác minh sẽ hiển thị sau khi tiếp tục."
                  onComplete={() => {
                    setReceiveFlowActive(false);
                    setReceiveComplete(Boolean(openedMessage));
                    const failedStep = receiveSteps.find((step) => step.status === "failed");
                    const warningStep = receiveSteps.find((step) => step.status === "warning");
                    if (failedStep) {
                      setNotice("open", {
                        kind: "error",
                        text: `Phát hiện lỗi tại bước “${failedStep.label}”. ${failedStep.value}`,
                      });
                    } else if (warningStep) {
                      setNotice("open", { kind: "info", text: warningStep.value });
                    } else {
                      setNotice("open", { kind: "success", text: "Đã hoàn tất quy trình nhận gói tin." });
                    }
                  }}
                  onCopyError={() => setNotice("open", { kind: "info", text: "Clipboard bị chặn. Hãy chọn giá trị để sao chép." })}
                />
              ) : (
                <>
              {receiveComplete && openedMessage && (
                <div className="decrypted-card returned-result">
                  <div className="decrypted-heading"><ShieldCheck size={18} /><strong>Nội dung đã giải mã</strong></div>
                  <div className="decrypted-message">{openedMessage}</div>
                  {signatureResult && (
                    <div className={`signature-result ${signatureResult.status}`}>
                      {signatureResult.status === "valid" ? <ShieldCheck size={17} /> : signatureResult.status === "unknown" ? <ShieldQuestion size={17} /> : <MessageCircleWarning size={17} />}
                      <span>{signatureResult.message}</span>
                    </div>
                  )}
                  {signatureResult?.status === "unknown" && (
                    <p className="import-tip">Để xác minh, chọn người gửi ở trên, bấm <strong>Export public</strong>, sau đó quay về danh tính nhận và import khóa công khai đó.</p>
                  )}
                </div>
              )}
              <label className="field-label" htmlFor="package-input">Gói tin ASCII armor</label>
              <textarea id="package-input" className="armor-input" value={packageInput} onChange={(event) => setPackageInput(event.target.value)} placeholder={"-----BEGIN PGP MESSAGE-----\nDán gói tin vào đây…"} rows={6} />
              <div className="form-grid">
                <div>
                  <label className="field-label" htmlFor="receiver">Danh tính nhận</label>
                  <select id="receiver" value={receiverId} onChange={(event) => setReceiverId(event.target.value)}>
                    {users.map((user) => <option key={user.id} value={user.id}>{user.name}{user.key ? " · có khóa riêng" : " · chưa có khóa"}</option>)}
                  </select>
                </div>
                <div>
                  <label className="field-label" htmlFor="receiver-passphrase">Passphrase người nhận</label>
                  <div className="input-with-icon"><KeyRound size={16} /><input id="receiver-passphrase" type="password" autoComplete="current-password" value={receiverPassphrase} onChange={(event) => setReceiverPassphrase(event.target.value)} placeholder="Mở khóa riêng để giải mã" /></div>
                </div>
              </div>
              <StatusMessage notice={notices.open} />
              <button type="button" className="button button-primary" onClick={() => void openMessage()} disabled={busy === "open"}>
                {busy === "open" ? <span className="spinner" /> : <UnlockKeyhole size={17} />}
                {busy === "open" ? "Đang xử lý…" : "Giải mã & xác minh"}
              </button>

                </>
              )}
            </div>
          </section>
        </div>

        <aside className="side-column" hidden={activeTab !== "keyring"}>
          <section id="panel-keyring" role="tabpanel" aria-labelledby="tab-keyring" hidden={activeTab !== "keyring"} className="panel keyring-panel">
            <SectionHeading
              icon={<KeyRound size={19} />}
              eyebrow="DANH TÍNH ĐANG CHỌN"
              title="Keyring"
              description={activeUser ? `${activeUser.name} · khóa của tôi và khóa đã import` : "Khóa công khai và khóa riêng"}
            />
            <div className="panel-content compact">
              {activeUser?.key && (
                <div className="key-entry own-key">
                  <div className="key-entry-icon"><LockKeyhole size={16} /></div>
                  <div className="key-entry-body"><strong>{activeUser.name}</strong><span>Khóa riêng được bảo vệ · RSA {activeUser.key.bits}</span><code>{activeUser.key.fingerprint}</code></div>
                  <span className="key-state"><Check size={13} /></span>
                </div>
              )}
              {contacts.map((contact) => (
                <div className="key-entry" key={contact.fingerprint}>
                  <div className="key-entry-icon public"><Fingerprint size={16} /></div>
                  <div className="key-entry-body"><strong>{contact.name}</strong><span>Khóa công khai đã import</span><code>{contact.fingerprint}</code></div>
                </div>
              ))}
              {!activeUser?.key && contacts.length === 0 && <div className="empty-state"><FileKey2 size={26} /><strong>Keyring đang trống</strong><span>Tạo khóa của bạn hoặc import một khóa công khai.</span></div>}
              <div className="key-actions">
                <button type="button" className="button button-primary button-full" onClick={() => { setNotice("modal", undefined); setKeyPassphrase(""); setKeyModalOpen(true); }}>
                  <Plus size={16} /> {activeUser?.key ? "Tạo lại khóa" : "Tạo bộ khóa"}
                </button>
                {activeUser?.key && <button type="button" className="button button-outline button-full" onClick={() => void exportPublicKey()}><ArrowDownToLine size={16} /> Export public</button>}
              </div>
              <StatusMessage notice={notices.key} />
              <div className="import-divider"><span>HOẶC IMPORT KHÓA CÔNG KHAI</span></div>
              <textarea className="armor-input import-input" value={publicKeyInput} onChange={(event) => setPublicKeyInput(event.target.value)} placeholder="-----BEGIN PGP PUBLIC KEY-----" rows={4} aria-label="Import khóa công khai" />
              <button type="button" className="button button-outline button-full import-button" onClick={() => void importPublicKey()} disabled={!publicKeyInput.trim()}><Upload size={15} /> Import khóa</button>
            </div>
          </section>

        </aside>
      </main>

      <footer className="page-footer"><span>PGP LAB · PHÒNG THỰC HÀNH MẬT MÃ</span><span>Được thiết kế cho mục đích giáo dục</span></footer>

      {keyModalOpen && (
        <Modal title={activeUser?.key ? "Tạo bộ khóa mới" : "Tạo bộ khóa"} description={`Tạo khóa RSA cho ${activeUser?.name || "danh tính này"}. Passphrase bảo vệ khóa riêng được lưu trên máy.`} onClose={() => setKeyModalOpen(false)}>
          <form className="modal-form" onSubmit={(event) => void generateKey(event)}>
            <label className="field-label" htmlFor="key-bits">Kích thước khóa</label>
            <select id="key-bits" value={keyBits} onChange={(event) => setKeyBits(Number(event.target.value))}><option value={2048}>RSA 2048 bit · khuyên dùng</option><option value={4096}>RSA 4096 bit · bảo mật cao hơn</option></select>
            <label className="field-label" htmlFor="key-passphrase">Passphrase · tối thiểu 8 ký tự</label>
            <input id="key-passphrase" type="password" minLength={8} autoComplete="new-password" value={keyPassphrase} onChange={(event) => setKeyPassphrase(event.target.value)} required />
            <p className="modal-hint"><LockKeyhole size={14} /> Không thể khôi phục khóa nếu quên passphrase.</p>
            <StatusMessage notice={notices.modal} />
            <div className="modal-actions"><button type="button" className="button button-quiet" onClick={() => setKeyModalOpen(false)}>Hủy</button><button type="submit" className="button button-primary" disabled={busy === "key"}>{busy === "key" ? <span className="spinner" /> : <KeyRound size={16} />}{busy === "key" ? "Đang tạo…" : "Tạo khóa"}</button></div>
          </form>
        </Modal>
      )}

      {userModalOpen && (
        <Modal title="Thêm danh tính" description="Mỗi danh tính có keyring và cặp khóa riêng biệt." onClose={() => setUserModalOpen(false)}>
          <form className="modal-form" onSubmit={(event) => void addUser(event)}>
            <label className="field-label" htmlFor="new-user">Tên danh tính</label>
            <input id="new-user" type="text" maxLength={60} value={newUserName} onChange={(event) => setNewUserName(event.target.value)} required autoFocus />
            <StatusMessage notice={notices.userModal} />
            <div className="modal-actions"><button type="button" className="button button-quiet" onClick={() => setUserModalOpen(false)}>Hủy</button><button type="submit" className="button button-primary" disabled={busy === "user"}>{busy === "user" ? <span className="spinner" /> : <Plus size={16} />}{busy === "user" ? "Đang thêm…" : "Thêm danh tính"}</button></div>
          </form>
        </Modal>
      )}
    </div>
  );
}
