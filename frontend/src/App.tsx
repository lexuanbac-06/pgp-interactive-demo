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
  Trash2,
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

type IdentityDraft = {
  message: string;
  encrypt: boolean;
  sign: boolean;
  recipientFingerprint: string;
  packageInput: string;
  publicKeyInput: string;
};

const EMPTY_IDENTITY_DRAFT: IdentityDraft = {
  message: "",
  encrypt: true,
  sign: true,
  recipientFingerprint: "",
  packageInput: "",
  publicKeyInput: "",
};

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || (
  window.location.hostname.endsWith(".onrender.com")
    ? window.location.origin
    : ""
)).replace(/\/$/, "");
const STATIC_PREVIEW = import.meta.env.BASE_URL !== "/" && !API_BASE_URL;
const PREVIEW_STATE: AppState = {
  users: [
    { id: "alice-preview", name: "Alice", key: { name: "Alice", fingerprint: "A1B2C3D4E5F60718", bits: 2048 } },
    { id: "bob-preview", name: "Bob", key: { name: "Bob", fingerprint: "B2C3D4E5F6071829", bits: 2048 } },
    { id: "eve-preview", name: "Eve", key: { name: "Eve", fingerprint: "E5F6071829A1B2C3", bits: 2048 } },
  ],
  selected_user_id: "alice-preview",
  contacts: [],
};

async function api<T>(path: string, body?: object, method?: "POST" | "DELETE"): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: method || (body === undefined ? "GET" : "POST"),
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
  const [hasEntered, setHasEntered] = useState(false);
  const [activeTab, setActiveTab] = useState<AppTab>("send");
  const [sendFlowActive, setSendFlowActive] = useState(false);
  const [receiveFlowActive, setReceiveFlowActive] = useState(false);
  const [composeStage, setComposeStage] = useState<1 | 2 | 3>(1);
  const [receiveStage, setReceiveStage] = useState<1 | 2 | 3>(1);

  const [identityDrafts, setIdentityDrafts] = useState<Record<string, IdentityDraft>>({});
  const [signerPassphrase, setSignerPassphrase] = useState("");
  const [receiverPassphrase, setReceiverPassphrase] = useState("");
  const [packageOutput, setPackageOutput] = useState("");

  const [sendSteps, setSendSteps] = useState<Step[]>([]);
  const [sendSessionId, setSendSessionId] = useState<string | null>(null);
  const [sendRecipientUserId, setSendRecipientUserId] = useState<string | null>(null);
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
  const [busy, setBusy] = useState("");

  const activeDraft = identityDrafts[activeId] || EMPTY_IDENTITY_DRAFT;
  const { message, encrypt, sign, recipientFingerprint, packageInput, publicKeyInput } = activeDraft;
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
  function setNotice(key: string, notice?: Notice) {
    setNotices((current) => ({ ...current, [key]: notice }));
  }

  function updateActiveDraft<K extends keyof IdentityDraft>(key: K, value: IdentityDraft[K]) {
    if (!activeId) return;
    updateDraftForUser(activeId, key, value);
  }

  function updateDraftForUser<K extends keyof IdentityDraft>(userId: string, key: K, value: IdentityDraft[K]) {
    setIdentityDrafts((current) => ({
      ...current,
      [userId]: { ...(current[userId] || EMPTY_IDENTITY_DRAFT), [key]: value },
    }));
  }

  async function refresh(selectedId?: string) {
    if (STATIC_PREVIEW) {
      const selected = selectedId || PREVIEW_STATE.selected_user_id || PREVIEW_STATE.users[0]?.id || "";
      setUsers(PREVIEW_STATE.users);
      setContacts(PREVIEW_STATE.contacts);
      setActiveId(selected);
      return selected;
    }
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
    if (recipientFingerprint && !recipients.some((item) => item.fingerprint === recipientFingerprint)) {
      setIdentityDrafts((current) => ({
        ...current,
        [activeId]: { ...(current[activeId] || EMPTY_IDENTITY_DRAFT), recipientFingerprint: "" },
      }));
    }
  }, [activeId, recipients, recipientFingerprint]);

  async function selectUser(userId: string) {
    setActiveTab("send");
    setNotices({});
    setComposeStage(1);
    setReceiveStage(1);
    setSignerPassphrase("");
    setReceiverPassphrase("");
    setKeyPassphrase("");
    setPackageOutput("");
    setSendSteps([]);
    setSendSessionId(null);
    setSendRecipientUserId(null);
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
    if (STATIC_PREVIEW) {
      setActiveId(userId);
      return;
    }
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
    const userId = activeId;
    try {
      const result = await api<{ armored: string }>("/api/keys/export", { user_id: userId });
      updateDraftForUser(userId, "publicKeyInput", result.armored);
      await copy(result.armored, "Đã export và sao chép khóa công khai.", "key");
    } catch (error) {
      setNotice("key", { kind: "error", text: getErrorMessage(error) });
    }
  }

  async function importPublicKey() {
    const userId = activeId;
    const armored = publicKeyInput;
    setNotice("key", undefined);
    try {
      const result = await api<{ key: Identity }>("/api/keys/import", {
        user_id: userId,
        armored,
      });
      updateDraftForUser(userId, "publicKeyInput", "");
      await refresh(userId);
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
      setActiveTab("send");
      await refresh(result.user.id);
    } catch (error) {
      setNotice("userModal", { kind: "error", text: getErrorMessage(error) });
    } finally {
      setBusy("");
    }
  }

  async function deleteUser(user: User) {
    if (STATIC_PREVIEW) {
      setNotice("identity", { kind: "info", text: "Tính năng xóa danh tính cần chạy ứng dụng bằng máy chủ Python cục bộ." });
      return;
    }
    if (users.length <= 1) {
      setNotice("identity", { kind: "error", text: "Không thể xóa danh tính cuối cùng." });
      return;
    }
    if (!window.confirm(`Xóa danh tính “${user.name}” cùng toàn bộ khóa riêng và keyring của danh tính này? Thao tác này không thể hoàn tác.`)) return;

    setBusy(`delete-user:${user.id}`);
    setNotice("identity", undefined);
    const wasActive = user.id === activeId;
    let refreshUserId = activeId;
    if (wasActive) setActiveTab("send");
    try {
      if (STATIC_PREVIEW) {
        const remainingUsers = users.filter((item) => item.id !== user.id);
        if (wasActive) refreshUserId = remainingUsers[0]?.id || "";
        setUsers(remainingUsers);
        if (wasActive) setActiveId(refreshUserId);
      } else {
        const result = await api<{ next_user_id: string | null }>(
          "/api/users",
          { user_id: user.id },
          "DELETE",
        );
        if (wasActive) refreshUserId = result.next_user_id || "";
        setUsers((current) => current.filter((item) => item.id !== user.id));
        if (wasActive) setActiveId(refreshUserId);
        await refresh(refreshUserId || undefined);
      }

      setContacts([]);
      setSendSteps([]);
      setSendSessionId(null);
      setSendRecipientUserId(null);
      setSendRunId((current) => current + 1);
      setReceiveSteps([]);
      setReceiveSessionId(null);
      setReceiveRunId((current) => current + 1);
      setSendFlowActive(false);
      setReceiveFlowActive(false);
      setSendComplete(false);
      setReceiveComplete(false);
      setPackageOutput("");
      setOpenedMessage("");
      setSignatureResult(null);
      setSignerPassphrase("");
      setReceiverPassphrase("");
      setIdentityDrafts((current) => {
        const remaining = { ...current };
        delete remaining[user.id];
        return remaining;
      });
      setNotice("identity", { kind: "success", text: `Đã xóa danh tính “${user.name}” và keyring của danh tính này.` });
    } catch (error) {
      setNotice("identity", { kind: "error", text: getErrorMessage(error) });
      if (!STATIC_PREVIEW) {
        try {
          await refresh(refreshUserId || undefined);
        } catch (refreshError) {
          setNotice("identity", { kind: "error", text: `${getErrorMessage(error)} Không thể tải lại danh sách: ${getErrorMessage(refreshError)}` });
        }
      }
    } finally {
      setBusy("");
    }
  }

  async function compose() {
    const senderId = activeId;
    const recipientUserId = users.find((user) => user.key?.fingerprint === recipientFingerprint)?.id || null;
    if (!message.trim()) {
      setNotice("compose", { kind: "error", text: "Hãy nhập nội dung tin nhắn." });
      setComposeStage(1);
      return;
    }
    if (!recipientFingerprint) {
      setNotice("compose", { kind: "error", text: "Hãy chọn khóa công khai người nhận." });
      setComposeStage(1);
      return;
    }
    if (sign && !signerPassphrase) {
      setNotice("compose", { kind: "error", text: "Hãy nhập passphrase để ký bằng khóa riêng của người gửi." });
      setComposeStage(2);
      return;
    }
    setBusy("compose");
    setNotice("compose", undefined);
    setSendSteps([]);
    setSendComplete(false);
    setSendSessionId(null);
    setSendRecipientUserId(recipientUserId);
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
        sender_id: senderId,
        message,
        encrypt,
        recipient_fingerprint: recipientFingerprint,
        sign,
        signer_id: senderId,
        signer_passphrase: signerPassphrase,
      });
      setPackageOutput(result.result?.armored || "");
      if (result.result?.armored && recipientUserId) {
        updateDraftForUser(recipientUserId, "packageInput", result.result.armored);
      }
      setSendSessionId(result.session_id);
      setSendTotalSteps(result.total_steps);
      setSendSteps([result.step]);
      setSendFlowActive(true);
      setSignerPassphrase("");
      setNotice("compose", undefined);
      setActiveTab("send");
      window.requestAnimationFrame(() => {
        document.getElementById("panel-send")?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    } catch (error) {
      setSendRecipientUserId(null);
      setNotice("compose", { kind: "error", text: getErrorMessage(error) });
    } finally {
      setBusy("");
    }
  }

  function advanceComposeStage() {
    setNotice("compose", undefined);
    if (composeStage === 1) {
      if (!message.trim()) {
        setNotice("compose", { kind: "error", text: "Hãy nhập nội dung tin nhắn." });
        return;
      }
      if (!recipientFingerprint) {
        setNotice("compose", { kind: "error", text: "Hãy chọn khóa công khai người nhận." });
        return;
      }
      setComposeStage(2);
      return;
    }

    if (composeStage === 2) {
      if (sign && !signerPassphrase) {
        setNotice("compose", { kind: "error", text: "Hãy nhập passphrase để ký bằng khóa riêng của người gửi." });
        return;
      }
      setComposeStage(3);
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
        if (sendRecipientUserId) {
          updateDraftForUser(sendRecipientUserId, "packageInput", result.result.armored);
        }
      }
      return { step: result.step, done: result.done };
    } catch (error) {
      setNotice("compose", { kind: "error", text: getErrorMessage(error) });
      return undefined;
    }
  }

  async function openMessage() {
    if (!packageInput.trim()) {
      setNotice("open", { kind: "error", text: "Hãy dán gói tin cần nhận." });
      setReceiveStage(1);
      return;
    }
    if (!activeUser?.key) {
      setNotice("open", { kind: "error", text: "Danh tính đang chọn chưa có khóa riêng để nhận thông điệp." });
      setReceiveStage(2);
      return;
    }
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
        user_id: activeId,
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

  function advanceReceiveStage() {
    setNotice("open", undefined);
    if (receiveStage === 1) {
      if (!packageInput.trim()) {
        setNotice("open", { kind: "error", text: "Hãy dán gói tin cần nhận." });
        return;
      }
      setReceiveStage(2);
      return;
    }
    if (receiveStage === 2) {
      if (!activeUser?.key) {
        setNotice("open", { kind: "error", text: "Danh tính đang chọn chưa có khóa riêng để nhận thông điệp." });
        return;
      }
      setReceiveStage(3);
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

  if (!hasEntered) {
    return (
      <main className="welcome-screen">
        <section className="welcome-window" aria-labelledby="welcome-title">
          <div className="welcome-art" aria-hidden="true">
            <div className="welcome-art-glow" />
            <div className="welcome-orbit welcome-orbit-one" />
            <div className="welcome-orbit welcome-orbit-two" />
            <div className="welcome-lock"><LockKeyhole size={54} strokeWidth={1.5} /></div>
            <span className="welcome-chip welcome-chip-key"><KeyRound size={18} /></span>
            <span className="welcome-chip welcome-chip-shield"><ShieldCheck size={18} /></span>
          </div>
          <div className="welcome-content">
            <div className="welcome-brand">
              <span className="brand-symbol"><LockKeyhole size={20} /></span>
              <span><strong>PGP<span>Lab</span></strong><small>CRYPTOGRAPHY PLAYGROUND</small></span>
            </div>
            <span className="eyebrow">PHÒNG THỰC HÀNH MẬT MÃ</span>
            <h1 id="welcome-title">Chào mừng đến với demo PGP</h1>
            <p className="welcome-lead">Cùng khám phá cách mã hóa và xác thực thông điệp qua trải nghiệm tương tác từng bước.</p>
            <ul className="welcome-features">
              <li><KeyRound size={16} /><span>Tạo và quản lý khóa công khai, khóa riêng</span></li>
              <li><LockKeyhole size={16} /><span>Mô phỏng gửi và giải mã thông điệp</span></li>
              <li><Fingerprint size={16} /><span>Quan sát quá trình ký và xác minh chữ ký số</span></li>
            </ul>
            <div className="welcome-disclaimer">
              <ShieldQuestion size={16} />
              <p>Đây là sản phẩm mô phỏng phục vụ học tập, không tương thích OpenPGP và không dùng để bảo vệ dữ liệu thật.</p>
            </div>
            <div className="welcome-actions">
              <span>Nhấn “Tiếp tục” để bắt đầu.</span>
              <button type="button" className="button button-primary" onClick={() => setHasEntered(true)}>
                Tiếp tục <ArrowRight size={16} />
              </button>
            </div>
          </div>
        </section>
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
          <span className="local-indicator"><span /> {STATIC_PREVIEW ? "Bản xem giao diện" : "Đang chạy cục bộ"}</span>
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
        <p>
          <strong>{STATIC_PREVIEW ? "Bản xem giao diện GitHub Pages." : "Mô phỏng an toàn để học tập."}</strong>{" "}
          {STATIC_PREVIEW
            ? "Các thao tác mật mã cần chạy bản Python cục bộ bằng hướng dẫn trong README."
            : "Gói tin dùng RSA-PSS, RSA-OAEP, AES-256-GCM và SHA-256, nhưng định dạng không tương thích OpenPGP — không dùng để bảo vệ dữ liệu thật."}
        </p>
      </div>

      <nav className="user-switcher" aria-label="Danh tính">
        <div className="user-switcher-label">DANH TÍNH</div>
        <div className="user-tabs">
          {users.map((user) => (
            <div className={`user-choice ${activeId === user.id ? "active" : ""}`} key={user.id}>
              <button type="button" className={`user-tab ${activeId === user.id ? "active" : ""}`} onClick={() => void selectUser(user.id)}>
                <span className="avatar">{user.name.slice(0, 1).toUpperCase()}</span>
                <span>{user.name}</span>
                {user.key && <span className="user-key-dot" title="Đã có khóa" />}
              </button>
              <button
                type="button"
                className="delete-user-button"
                aria-label={`Xóa danh tính ${user.name}`}
                title={STATIC_PREVIEW ? "Xóa danh tính cần máy chủ Python cục bộ" : users.length === 1 ? "Không thể xóa danh tính cuối cùng" : `Xóa danh tính ${user.name}`}
                disabled={STATIC_PREVIEW || users.length <= 1 || busy.startsWith("delete-user:")}
                onClick={() => void deleteUser(user)}
              >
                <Trash2 size={18} />
              </button>
            </div>
          ))}
        </div>
        <button type="button" className="add-user-button" onClick={() => { setNotice("userModal", undefined); setUserModalOpen(true); }}>
          <Plus size={16} /> Thêm danh tính
        </button>
      </nav>
      <StatusMessage notice={notices.identity} />

      <nav className="app-tabs" role="tablist" aria-label="Khu vực ứng dụng">
        <button type="button" role="tab" id="tab-send" aria-selected={activeTab === "send"} aria-controls="panel-send" className={`app-tab ${activeTab === "send" ? "active" : ""}`} onClick={() => setActiveTab("send")}>
          <Mail size={22} /><span>Gửi</span><small>Tạo và ký gói tin</small>
        </button>
        <button type="button" role="tab" id="tab-receive" aria-selected={activeTab === "receive"} aria-controls="panel-receive" className={`app-tab ${activeTab === "receive" ? "active" : ""}`} onClick={() => setActiveTab("receive")}>
          <UnlockKeyhole size={22} /><span>Nhận</span><small>Giải mã và xác minh</small>
        </button>
        <button type="button" role="tab" id="tab-keyring" aria-selected={activeTab === "keyring"} aria-controls="panel-keyring" className={`app-tab ${activeTab === "keyring" ? "active" : ""}`} onClick={() => setActiveTab("keyring")}>
          <KeyRound size={22} /><span>Keyring</span><small>Quản lý khóa</small>
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
                    setComposeStage(1);
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
              <div className="compose-progress" aria-label={`Bước ${composeStage} trên 3`}>
                {[
                  { number: 1, title: "Soạn tin nhắn" },
                  { number: 2, title: "Bảo mật" },
                  { number: 3, title: "Xác nhận gửi" },
                ].map((stage) => (
                  <div key={stage.number} className={`compose-progress-step ${composeStage === stage.number ? "active" : composeStage > stage.number ? "done" : ""}`}>
                    <span>{composeStage > stage.number ? <Check size={16} /> : stage.number}</span>
                    <strong>{stage.title}</strong>
                  </div>
                ))}
              </div>

              {composeStage === 1 && (
                <div className="compose-stage">
                  <h3>Bước 1: Soạn tin nhắn và chọn người nhận</h3>
                  <label className="field-label" htmlFor="message">Nội dung tin nhắn</label>
                  <textarea
                    id="message"
                    className="message-input"
                    value={message}
                    onChange={(event) => updateActiveDraft("message", event.target.value)}
                    placeholder="Viết một thông điệp cần gửi…"
                    rows={4}
                  />
                  <div className="form-grid">
                    <div>
                      <label className="field-label" htmlFor="recipient">Người nhận</label>
                      <select id="recipient" value={recipientFingerprint} onChange={(event) => updateActiveDraft("recipientFingerprint", event.target.value)}>
                        <option value="">Chọn người nhận</option>
                        {recipients.map((recipient) => <option key={recipient.fingerprint} value={recipient.fingerprint}>{recipient.name} · {recipient.fingerprint.slice(0, 15)}…</option>)}
                      </select>
                    </div>
                    <div className="field-hint">
                      <span className="field-label">Người gửi</span>
                      <span>{activeUser ? `${activeUser.name} · danh tính đang chọn` : "Chọn một danh tính"}</span>
                    </div>
                  </div>
                </div>
              )}

              {composeStage === 2 && (
                <div className="compose-stage">
                  <h3>Bước 2: Nhập passphrase và chọn tùy chọn bảo mật</h3>
                  {sign && (
                    <div className="field-block">
                      <label className="field-label" htmlFor="signer-passphrase">Passphrase khóa riêng người gửi</label>
                      <div className="input-with-icon"><KeyRound size={16} /><input id="signer-passphrase" type="password" autoComplete="current-password" value={signerPassphrase} onChange={(event) => setSignerPassphrase(event.target.value)} placeholder="Dùng để mở khóa riêng cục bộ" /></div>
                    </div>
                  )}
                  <div className="option-row">
                    <label className={`option-card ${sign ? "selected" : ""}`}>
                      <input type="checkbox" checked={sign} onChange={(event) => updateActiveDraft("sign", event.target.checked)} />
                      <span className="option-icon"><Fingerprint size={17} /></span>
                      <span><strong>Ký số</strong><small>Xác minh người gửi</small></span>
                      <span className="toggle"><i /></span>
                    </label>
                    <label className={`option-card ${encrypt ? "selected" : ""}`}>
                      <input type="checkbox" checked={encrypt} onChange={(event) => updateActiveDraft("encrypt", event.target.checked)} />
                      <span className="option-icon"><LockKeyhole size={17} /></span>
                      <span><strong>Mã hóa</strong><small>Chỉ người nhận đọc được</small></span>
                      <span className="toggle"><i /></span>
                    </label>
                  </div>
                </div>
              )}

              {composeStage === 3 && (
                <div className="compose-stage">
                  <h3>Bước 3: Kiểm tra và xác nhận gửi</h3>
                  <div className="send-review">
                    <div><span>Người gửi</span><strong>{activeUser?.name || "Chưa chọn"}</strong></div>
                    <div><span>Người nhận</span><strong>{recipients.find((recipient) => recipient.fingerprint === recipientFingerprint)?.name || "Chưa chọn"}</strong></div>
                    <div><span>Bảo mật</span><strong>{[sign ? "Có chữ ký số" : "Không ký số", encrypt ? "Có mã hóa" : "Không mã hóa"].join(" · ")}</strong></div>
                    <div className="send-review-message"><span>Nội dung</span><p>{message}</p></div>
                  </div>
                  <p className="send-review-note">Sau khi xác nhận, ứng dụng sẽ tạo gói tin theo các tùy chọn trên. Bạn có thể sao chép gói tin để gửi cho người nhận.</p>
                </div>
              )}

              <StatusMessage notice={notices.compose} />
              <div className="compose-controls">
                {composeStage > 1 ? (
                  <button type="button" className="button button-quiet" onClick={() => { setNotice("compose", undefined); setComposeStage((stage) => stage === 3 ? 2 : 1); }} disabled={busy === "compose"}>
                    <ArrowLeft size={17} /> Quay lại
                  </button>
                ) : <span />}
                {composeStage < 3 ? (
                  <button type="button" className="button button-primary" onClick={advanceComposeStage}>
                    Tiếp theo <ArrowRight size={17} />
                  </button>
                ) : (
                  <button type="button" className="button button-primary send-button" onClick={() => void compose()} disabled={busy === "compose"}>
                    {busy === "compose" ? <span className="spinner" /> : <ShieldCheck size={17} />}
                    {busy === "compose" ? "Đang tạo gói tin…" : "Xác nhận & tạo gói tin"}
                  </button>
                )}
              </div>

                </>
              )}
            </div>
          </section>

          <section id="panel-receive" role="tabpanel" aria-labelledby="tab-receive" hidden={activeTab !== "receive"} className={`panel receive-panel ${receiveFlowActive ? "flow-panel" : ""}`}>
            <SectionHeading
              icon={<UnlockKeyhole size={19} />}
              eyebrow={receiveFlowActive ? "QUY TRÌNH MẬT MÃ · PHÍA NHẬN" : "02 · NHẬN THÔNG ĐIỆP"}
              title={receiveFlowActive ? "Đang xử lý gói tin" : "Giải mã & xác minh"}
              description={receiveFlowActive ? `Theo dõi lần lượt các bước giải mã${activeUser ? ` · ${activeUser.name}` : ""}.` : "Dán gói tin, chọn danh tính nhận và xác minh chữ ký."}
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
                    setReceiveStage(1);
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
              <div className="compose-progress" aria-label={`Bước ${receiveStage} trên 3`}>
                {[
                  { number: 1, title: "Nhập gói tin" },
                  { number: 2, title: "Nhập passphrase" },
                  { number: 3, title: "Xác nhận nhận" },
                ].map((stage) => (
                  <div key={stage.number} className={`compose-progress-step ${receiveStage === stage.number ? "active" : receiveStage > stage.number ? "done" : ""}`}>
                    <span>{receiveStage > stage.number ? <Check size={16} /> : stage.number}</span>
                    <strong>{stage.title}</strong>
                  </div>
                ))}
              </div>

              {receiveStage === 1 && (
                <div className="compose-stage">
                  <h3>Bước 1: Nhập gói tin cần nhận</h3>
                  <label className="field-label" htmlFor="package-input">Gói tin PGP</label>
                  <textarea id="package-input" className="armor-input" value={packageInput} onChange={(event) => updateActiveDraft("packageInput", event.target.value)} placeholder={"-----BEGIN PGP MESSAGE-----\nDán gói tin vào đây…"} rows={6} />
                </div>
              )}

              {receiveStage === 2 && (
                <div className="compose-stage">
                  <h3>Bước 2: Nhập passphrase để mở khóa riêng</h3>
                  <div className="receiver-passphrase-context">
                    <UserRound size={19} />
                    <div>
                      <strong>{activeUser?.name || "Chưa chọn danh tính"}</strong>
                      <span>Danh tính nhận đang được chọn ở phía trên</span>
                    </div>
                  </div>
                  <div className="field-block receiver-passphrase-field">
                    <label className="field-label" htmlFor="receiver-passphrase">Passphrase khóa riêng</label>
                    <div className="input-with-icon"><KeyRound size={16} /><input id="receiver-passphrase" type="password" autoComplete="current-password" value={receiverPassphrase} onChange={(event) => setReceiverPassphrase(event.target.value)} placeholder="Nhập passphrase để giải mã" /></div>
                  </div>
                  <p className="send-review-note">Passphrase chỉ dùng cục bộ để mở khóa riêng, không được gửi đi.</p>
                </div>
              )}

              {receiveStage === 3 && (
                <div className="compose-stage">
                  <h3>Bước 3: Kiểm tra và xác nhận nhận</h3>
                  <div className="send-review">
                    <div><span>Danh tính nhận</span><strong>{activeUser?.name || "Chưa chọn"}</strong></div>
                    <div><span>Khóa riêng</span><strong>{activeUser?.key ? "Đã có" : "Chưa có"}</strong></div>
                    <div className="send-review-message">
                      <span>Gói tin</span>
                      <p>{packageInput.trim() ? packageInput.trim() : "Chưa nhập gói tin"}</p>
                    </div>
                  </div>
                  <p className="send-review-note">Xác nhận để bắt đầu lần lượt các bước giải mã và xác minh chữ ký số.</p>
                </div>
              )}

              <StatusMessage notice={notices.open} />
              <div className="compose-controls">
                {receiveStage > 1 ? (
                  <button type="button" className="button button-quiet" onClick={() => { setNotice("open", undefined); setReceiveStage((stage) => stage === 3 ? 2 : 1); }} disabled={busy === "open"}>
                    <ArrowLeft size={17} /> Quay lại
                  </button>
                ) : <span />}
                {receiveStage < 3 ? (
                  <button type="button" className="button button-primary" onClick={advanceReceiveStage}>
                    Tiếp theo <ArrowRight size={17} />
                  </button>
                ) : (
                  <button type="button" className="button button-primary" onClick={() => void openMessage()} disabled={busy === "open"}>
                    {busy === "open" ? <span className="spinner" /> : <UnlockKeyhole size={17} />}
                    {busy === "open" ? "Đang xử lý…" : "Xác nhận & giải mã"}
                  </button>
                )}
              </div>

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
              <textarea className="armor-input import-input" value={publicKeyInput} onChange={(event) => updateActiveDraft("publicKeyInput", event.target.value)} placeholder="-----BEGIN PGP PUBLIC KEY-----" rows={4} aria-label="Import khóa công khai" />
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
