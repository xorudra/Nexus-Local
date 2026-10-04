export function textContent(message) {
    return typeof message.content === 'string' ? message.content : null;
}
export function withTextContent(message, content) {
    return { ...message, content };
}
export function messageChars(messages) {
    return messages.reduce((sum, message) => {
        if (typeof message.content === 'string')
            return sum + message.content.length;
        if (!Array.isArray(message.content))
            return sum;
        return sum + message.content.reduce((n, block) => {
            if (typeof block === 'string')
                return n + block.length;
            return n + (typeof block?.text === 'string' ? block.text.length : 0);
        }, 0);
    }, 0);
}
export function estimateTokensFromChars(chars) {
    return Math.ceil(chars / 4);
}
export function buildToolCallOrigins(messages) {
    const origins = new Map();
    messages.forEach((message, messageIndex) => {
        for (const call of message.tool_calls ?? []) {
            if (!call.id)
                continue;
            origins.set(call.id, {
                id: call.id,
                name: call.function.name,
                arguments: call.function.arguments,
                messageIndex,
            });
        }
    });
    return origins;
}
export function allMessageText(messages) {
    return messages.map(message => {
        if (typeof message.content === 'string')
            return message.content;
        if (!Array.isArray(message.content))
            return '';
        return message.content.map(block => {
            if (typeof block === 'string')
                return block;
            return typeof block?.text === 'string' ? block.text : '';
        }).join('');
    }).join('\n');
}
//# sourceMappingURL=helpers.js.map