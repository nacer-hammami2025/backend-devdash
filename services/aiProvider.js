// aiProvider.js
// Low-level provider wrapper (OpenAI now, can add others later)

const OpenAI = require('openai');

class AIProvider {
    constructor(opts = {}) {
        this.enabled = !!process.env.OPENAI_API_KEY;
        this.model = opts.model || process.env.OPENAI_MODEL || 'gpt-4o-mini';
        if (this.enabled) {
            this.client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
        }
    }

    async complete({ system, prompt, temperature = 0.4, maxTokens = 600 }) {
        if (!this.enabled) {
            return { text: '[AI désactivée - aucune clé API]', usage: { total_tokens: 0 } };
        }
        const messages = [];
        if (system) messages.push({ role: 'system', content: system });
        messages.push({ role: 'user', content: prompt });

        const response = await this.client.chat.completions.create({
            model: this.model,
            messages,
            temperature,
            max_tokens: maxTokens
        });
        const choice = response.choices[0];
        return {
            text: choice.message.content.trim(),
            usage: response.usage || { total_tokens: null }
        };
    }
}

module.exports = { AIProvider };
