from app.agent.llm_compat import (
    apply_temperature,
    model_profile,
    param_to_drop,
    prepare_chat_body,
    preserves_assistant_reasoning,
    sampling_temperature,
    uses_fixed_sampling,
)


def test_kimi_k3_family_uses_fixed_sampling():
    for model in (
        "kimi-k3",
        "Kimi-K3",
        "moonshotai/kimi-k3",
        "kimi-k3-preview",
        "kimi-k2.5",
        "kimi-k2.6",
        "kimi-k2.7-code",
        "kimi-k2.7-code-highspeed",
        "openmodel-kimi-k2.5",
    ):
        assert uses_fixed_sampling(model), model
        assert sampling_temperature(model, 0.2) is None
        assert preserves_assistant_reasoning(model)
        assert model_profile(model).prefer_max_completion_tokens


def test_deepseek_reasoner_omits_temperature():
    assert uses_fixed_sampling("deepseek-reasoner")
    assert uses_fixed_sampling("deepseek-r1")
    assert preserves_assistant_reasoning("deepseek-reasoner")
    assert sampling_temperature("deepseek-chat", 0.2) == 0.2


def test_glm_and_qwen_thinking_keep_reasoning():
    assert preserves_assistant_reasoning("glm-5.2")
    assert preserves_assistant_reasoning("glm-4.5-air")
    assert preserves_assistant_reasoning("qwen3-max")
    assert not uses_fixed_sampling("glm-5.2")
    assert sampling_temperature("glm-5.2", 0.2) == 0.2


def test_openai_reasoning_and_claude_opus_omit_temperature():
    assert uses_fixed_sampling("o3-mini")
    assert uses_fixed_sampling("gpt-5")
    assert uses_fixed_sampling("gpt-5-mini")
    assert uses_fixed_sampling("claude-opus-4-6")
    assert model_profile("gpt-5").prefer_max_completion_tokens
    assert not preserves_assistant_reasoning("gpt-5")
    assert not uses_fixed_sampling("gpt-4o")
    assert not uses_fixed_sampling("claude-sonnet-4")


def test_other_models_keep_temperature():
    for model in (
        "gpt-4o",
        "kimi-k2-0711-preview",
        "kimi-latest",
        "moonshot-v1-32k",
        "kimi-k2-turbo-preview",
    ):
        assert not uses_fixed_sampling(model), model
        assert sampling_temperature(model, 0.2) == 0.2
        assert not preserves_assistant_reasoning(model)


def test_apply_temperature_omits_or_sets():
    body = {"model": "kimi-k3"}
    apply_temperature(body, "kimi-k3", 0.2)
    assert "temperature" not in body
    apply_temperature(body, "glm-5.2", 0.2)
    assert body["temperature"] == 0.2


def test_prepare_chat_body_remaps_max_tokens_for_kimi_k3():
    body = prepare_chat_body(
        {"model": "kimi-k3", "max_tokens": 16, "temperature": 0.2},
        "kimi-k3",
        temperature=0.2,
    )
    assert "temperature" not in body
    assert "max_tokens" not in body
    assert body["max_completion_tokens"] == 16


def test_param_to_drop_prefers_named_field():
    body = {"temperature": 0.2, "stream_options": {"include_usage": True}, "top_p": 0.9}
    assert param_to_drop(body, "Parameter 'top_p' is not supported") == "top_p"
    assert param_to_drop(body, "Parameter 'temperature'=0.2 is not supported") == "temperature"
    assert param_to_drop(body, "unknown parameter stream_options") == "stream_options"
    assert param_to_drop({"model": "x", "messages": []}, "bad request") is None


def test_apply_disable_thinking_for_default_thinking_models():
    from app.agent.llm_compat import apply_disable_thinking

    kimi = apply_disable_thinking({"model": "kimi-k3"}, "kimi-k3")
    assert kimi["thinking"] == {"type": "disabled"}

    glm = apply_disable_thinking({"model": "glm-5.2"}, "glm-5.2")
    assert glm["thinking"] == {"type": "disabled"}

    qwen = apply_disable_thinking({"model": "qwen3-max"}, "qwen3-max")
    assert qwen["enable_thinking"] is False

    o3 = apply_disable_thinking({"model": "o3-mini"}, "o3-mini")
    assert o3["reasoning_effort"] == "low"

    gpt = apply_disable_thinking({"model": "gpt-4o"}, "gpt-4o")
    assert "thinking" not in gpt
    assert "enable_thinking" not in gpt

    claude = apply_disable_thinking({"model": "claude-sonnet-4"}, "claude-sonnet-4", anthropic=True)
    assert "thinking" not in claude


def test_param_to_drop_thinking_fields():
    body = {"thinking": {"type": "disabled"}, "enable_thinking": False}
    assert param_to_drop(body, "Unknown parameter: thinking") == "thinking"
    assert param_to_drop(body, "enable_thinking is not supported") == "enable_thinking"
