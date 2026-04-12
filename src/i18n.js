/**
 * Minimal i18n for Japanese / English.
 */

export const translations = {
  en: {
    title: 'TOTP Generator',
    subtitle: 'Local 2FA Code Generator',
    securityWarning: '⚠ Security Notice: Secrets are stored in localStorage. This is less secure than a dedicated authenticator app. Use at your own risk.',
    addAccount: '+ Add Account',
    noAccounts: 'No accounts yet. Add one to get started.',
    labelPlaceholder: 'Account label (e.g. user@example.com)',
    issuerPlaceholder: 'Issuer / Service name (optional)',
    secretPlaceholder: 'Base32 secret key (e.g. JBSWY3DPEHPK3PXP)',
    otpauthPlaceholder: 'Paste otpauth:// URL to import',
    orPasteUrl: 'Or paste an otpauth:// URL:',
    importFromUrl: 'Import from URL',
    add: 'Add',
    cancel: 'Cancel',
    copy: 'Copy',
    copied: 'Copied!',
    delete: 'Delete',
    confirmDelete: 'Delete this account?',
    exportAll: 'Export',
    importFile: 'Import',
    exportTitle: 'Export Accounts',
    importTitle: 'Import Accounts',
    exportPassword: 'Encrypt with password (optional):',
    importPassword: 'Password (if encrypted):',
    exportBtn: 'Download JSON',
    importBtn: 'Import',
    seconds: 's',
    invalidSecret: 'Invalid base32 secret.',
    invalidUrl: 'Invalid otpauth:// URL.',
    errorGenerate: 'Error generating code.',
    lang: 'Language',
    darkMode: 'Theme',
    addManually: 'Enter manually:',
    period: 'Period (s)',
    digits: 'Digits',
  },
  ja: {
    title: 'TOTP ジェネレータ',
    subtitle: 'ローカル 2FA コード生成',
    securityWarning: '⚠ セキュリティ注意: シークレットは localStorage に保存されます。専用の認証アプリより安全性が低い場合があります。自己責任でご利用ください。',
    addAccount: '+ アカウントを追加',
    noAccounts: 'アカウントがありません。追加してください。',
    labelPlaceholder: 'アカウント名（例: user@example.com）',
    issuerPlaceholder: 'サービス名（任意）',
    secretPlaceholder: 'Base32 シークレットキー（例: JBSWY3DPEHPK3PXP）',
    otpauthPlaceholder: 'otpauth:// URL を貼り付けてインポート',
    orPasteUrl: 'または otpauth:// URL を貼り付け:',
    importFromUrl: 'URL からインポート',
    add: '追加',
    cancel: 'キャンセル',
    copy: 'コピー',
    copied: 'コピーしました！',
    delete: '削除',
    confirmDelete: 'このアカウントを削除しますか？',
    exportAll: 'エクスポート',
    importFile: 'インポート',
    exportTitle: 'アカウントをエクスポート',
    importTitle: 'アカウントをインポート',
    exportPassword: 'パスワードで暗号化（任意）:',
    importPassword: 'パスワード（暗号化している場合）:',
    exportBtn: 'JSON をダウンロード',
    importBtn: 'インポート',
    seconds: '秒',
    invalidSecret: '無効な Base32 シークレットです。',
    invalidUrl: '無効な otpauth:// URL です。',
    errorGenerate: 'コード生成エラー。',
    lang: '言語',
    darkMode: 'テーマ',
    addManually: '手動で入力:',
    period: '有効期間（秒）',
    digits: '桁数',
  },
};

let currentLang = 'en';

export function setLang(lang) {
  if (translations[lang]) currentLang = lang;
}

export function getLang() {
  return currentLang;
}

export function t(key) {
  return (translations[currentLang] || translations.en)[key] || key;
}
