export function formatTimestamp(ts: number | null | undefined): string {
  if (!ts) return '暂无记录'
  const d = new Date(ts * 1000)
  const yyyy = d.getFullYear()
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  const hh = String(d.getHours()).padStart(2, '0')
  const min = String(d.getMinutes()).padStart(2, '0')
  const ss = String(d.getSeconds()).padStart(2, '0')
  return `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`
}

export function formatRelativeAge(ts: number | null | undefined): string {
  if (!ts) return '未上报'
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - ts)
  if (diff < 10) return '刚刚'
  if (diff < 60) return `${diff} 秒前`
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`
  return `${Math.floor(diff / 86400)} 天前`
}

export function lockStateLabel(state: string): string {
  switch (state) {
    case 'locked':
      return '已上锁'
    case 'unlocked':
      return '已开锁'
    default:
      return '未知'
  }
}

export function approvalLabel(status: string): string {
  switch (status) {
    case 'approved':
      return '已批准'
    case 'pending':
      return '待审批'
    case 'rejected':
      return '已拒绝'
    case 'revoked':
      return '已吊销'
    default:
      return status
  }
}

export function parseGroupsJson(jsonStr: string): string[] {
  try {
    const arr = JSON.parse(jsonStr)
    return Array.isArray(arr) ? arr.map(String) : []
  } catch {
    return []
  }
}

export function splitCommaList(input: string): string[] {
  return input
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}
