 
# 🧠 Technical Prompt for Claude AI: Generate a Markdown Guide Based on a Successful Implementation

## 🧩 Context

I have just successfully implemented a complex feature or logic in a real-world development environment. This implementation was rigorous, solved significant technical challenges, and represents a high-quality, practical solution.

## 🎯 Prompt Objective

I want you to assume the role of a **senior technical engineer specializing in documentation and knowledge transfer for AI (especially Claude AI)**.

Using **all the technical and practical knowledge you gained throughout the implementation process**, I want you to create a definitive and standalone `.md` Markdown guide, designed for **both human learning and training large language models**.

---

## 🧠 Role and Expected Style

<role>Expert engineer in distributed systems, advanced technical documentation, and language model training.</role>

<tone>Professional, clear, didactic, and focused on effective knowledge transfer.</tone>

<target_audience>
- Experienced software engineers implementing {{FEATURE_NAME_IN_UPPERCASE}}
- Language model trainers seeking high-quality code and documentation examples
</target_audience>

---

## ✍️ Generation Instructions for the Guide

<instructions>
1. Generate a fully self-contained, well-structured `.md` Markdown technical guide.
2. Break the content into logically organized sections with clear headers.
3. Include working code examples with comments and explanations.
4. Cite official documentation and relevant resources in each section (when applicable).
5. If the topic requires big additional files (e.g., `.js`, `.py`, `.env`, `.json`), generate those as separate content blocks and reference their names explicitly in the main guide.
6. Include a Claude-optimized XML-style prompt block (only if useful) using Anthropic’s tag structure.
7. Ensure the guide serves both as **developer documentation** and as **training data for a language model**.
</instructions>

---

## 📦 Output Specifications

<format>
- Final output: Markdown `.md` format
- Include any necessary technical files (provided in separate, labeled blocks)
- The guide must be fully self-explanatory and standalone
</format>

<structure>
1. Introduction and objectives of the feature
2. Architecture and core concepts involved
3. Step-by-step implementation breakdown
4. Well-commented source code
5. Testing and validation methodology
6. Error handling and debugging tips
7. Resources and official documentation
8. (Optional) Claude-specific prompt example using XML tags
9. (Optional) Additional files with references
</structure>

---

## 🧠 Guide Title

The main guide title must be:

```markdown
# 🧭 Technical Guide: Implementing {{FEATURE_NAME_IN_UPPERCASE}}
