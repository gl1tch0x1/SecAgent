# AI and Prompt Injection Assessment

Assess authorized AI features as data-flow and tool-permission boundaries. Use controlled canaries and test accounts; do not request real secrets or unauthorized tool actions.

1. Map the model's trusted instructions, user input, retrieval sources, browser content and available tools.
2. Place a harmless canary instruction in one lower-trust surface and compare against a baseline and an unrelated control.
3. Measure whether the model merely quotes the canary, follows it in its answer, or crosses a tool-permission boundary. These are different outcomes.
4. Verify any tool effect from independent logs or state reads. A model's claim that it acted is not proof.
5. Repeat with distinct benign canaries to test robustness while keeping attempts bounded by the operator's budget.
6. Record the exact trust boundary, input source, model configuration, observed response and required human review.

Do not promote an answer-style change to a confirmed vulnerability unless it causes a reproducible, unauthorized effect.
