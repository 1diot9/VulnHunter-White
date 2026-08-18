const OWNER_REPO = /^[\w.-]+\/[\w.-]+$/

export type ProjectGithubFields = {
  source_type?: string | null
  source_url?: string | null
  identity?: string | null
}

export function parseGithubOwnerRepo(raw: string | null | undefined): string | null {
  if (!raw) return null
  const m = raw.trim().match(/(?:github\.com[/:]|git@github\.com:)([^/\s]+)\/([^/\s#?]+)/i)
  if (!m) return null
  const owner = m[1]
  const repo = m[2].replace(/\.git$/i, '').replace(/\/+$/, '')
  if (!owner || !repo) return null
  return `${owner}/${repo}`
}

export function githubRepoHref(project: ProjectGithubFields): string | null {
  const fromUrl = parseGithubOwnerRepo(project.source_url)
  if (fromUrl) return `https://github.com/${fromUrl}`
  if (project.source_type === 'github' && project.identity && OWNER_REPO.test(project.identity)) {
    return `https://github.com/${project.identity}`
  }
  return null
}

export function githubRepoLabel(project: ProjectGithubFields): string | null {
  const fromUrl = parseGithubOwnerRepo(project.source_url)
  if (fromUrl) return fromUrl
  if (project.identity && OWNER_REPO.test(project.identity)) return project.identity
  return null
}
