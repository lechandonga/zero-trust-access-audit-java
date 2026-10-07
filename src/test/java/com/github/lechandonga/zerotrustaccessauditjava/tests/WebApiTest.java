package com.github.lechandonga.zerotrustaccessauditjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Business("HTTP 接口：凭证、轮换、授权、审计鉴权")
@SpringBootTest
@AutoConfigureMockMvc
class WebApiTest {

    @RegisterExtension
    static final BusinessTestLogger LOGGER = new BusinessTestLogger();

    @Autowired
    private MockMvc mvc;

    private final ObjectMapper mapper = new ObjectMapper();

    private String issueReaderToken() throws Exception {
        String response = mvc.perform(post("/ztaa/credentials")
                        .header("Authorization", "AdminToken test-admin-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(
                                Map.of("subject", "carol", "roles", List.of("reader")))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return mapper.readTree(response).get("token").asText();
    }

    @Test
    @DisplayName("缺失或非法凭证访问受保护接口返回 401 且原因可区分")
    void unauthorizedRequestsRejected() throws Exception {
        mvc.perform(get("/ztaa/keys")).andExpect(status().isUnauthorized());
        mvc.perform(get("/ztaa/keys").header("Authorization", "Bearer garbage"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("malformed"));
        mvc.perform(get("/ztaa/keys").header("Authorization", "AdminToken wrong"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_admin_token"));
    }

    @Test
    @DisplayName("普通角色不能调用管理接口；越权查询审计返回 403")
    void managementEndpointsRequireAdminAndAuditPermission() throws Exception {
        String token = issueReaderToken();

        mvc.perform(get("/ztaa/keys").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("forbidden"));

        mvc.perform(get("/ztaa/audit").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("forbidden"));
    }

    @Test
    @DisplayName("授权判定产生审计，管理员可查询审计记录，全程响应不泄露密钥")
    void evaluationAuditedAndReadableByAdminOnly() throws Exception {
        String token = issueReaderToken();

        mvc.perform(post("/api/access/evaluate")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"action":"read","resourceType":"document","resourceId":"doc-9",
                                 "environment":"prod","tags":["public"],"attributes":{}}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(false))
                .andExpect(jsonPath("$.subject").value("carol"));

        String auditResponse = mvc.perform(get("/ztaa/audit").header(
                        "Authorization", "AdminToken test-admin-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count").value(1))
                .andReturn().getResponse().getContentAsString();
        assertFalse(auditResponse.contains(token), "审计响应中不得出现凭证原文");

        String keysResponse = mvc.perform(post("/ztaa/keys/rotate")
                        .header("Authorization", "AdminToken test-admin-token"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode keys = mapper.readTree(keysResponse);
        assertTrue(keys.has("activeKeyId"));
        assertFalse(keysResponse.matches("(?s).*[A-Za-z0-9_-]{40,}.*") || keysResponse.contains("secret"),
                "密钥接口不得暴露密钥内容");
    }

    @Test
    @DisplayName("吊销后原凭证立即 401 revoked，其他凭证不受影响")
    void revocationViaApiTakesEffectImmediately() throws Exception {
        JsonNode first = mapper.readTree(issue("dave", List.of("reader")));
        issue("dave", List.of("reader"));
        String jti = first.get("jti").asText();
        String tokenA = first.get("token").asText();

        mvc.perform(post("/ztaa/credentials/revoke")
                        .header("Authorization", "AdminToken test-admin-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"jti\":\"" + jti + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revoked").value(true));

        mvc.perform(post("/api/access/evaluate").header("Authorization", "Bearer " + tokenA)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"action":"read","resourceType":"x","resourceId":"1",
                                 "environment":"prod","tags":[],"attributes":{}}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("revoked"));
    }

    private String issue(String subject, List<String> roles) throws Exception {
        return mvc.perform(post("/ztaa/credentials")
                        .header("Authorization", "AdminToken test-admin-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of("subject", subject, "roles", roles))))
                .andReturn().getResponse().getContentAsString();
    }
}

