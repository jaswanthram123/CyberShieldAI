
package com.cybershield;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;

import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityApiTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void healthApiShouldBePublic() throws Exception {
        mockMvc.perform(get("/api/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void scansApiShouldRequireAuthentication() throws Exception {
        mockMvc.perform(get("/api/scans"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void scanCountShouldRequireAuthentication() throws Exception {
        mockMvc.perform(get("/api/scans/count"))
                .andExpect(status().isUnauthorized());
    }
}
