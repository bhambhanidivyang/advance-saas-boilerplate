export function generateEmailTemplateUrl(url: string, token: string) {
    return `${url}${encodeURIComponent(token)}`
}