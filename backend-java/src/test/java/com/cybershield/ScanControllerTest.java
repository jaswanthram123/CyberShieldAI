
package com.cybershield;

import com.cybershield.controller.ScanController;
import com.cybershield.service.ScanService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Optional;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class ScanControllerTest {

    private MockMvc mockMvc;
    private ScanService scanService;

    @BeforeEach
    void setup() {
        scanService = mock(ScanService.class);

        ScanController controller =
                new ScanController(scanService);

        mockMvc = MockMvcBuilders
                .standaloneSetup(controller)
                .build();
    }

    @Test
    void scanCountShouldReturn200() throws Exception {
        when(scanService.getTotalScans()).thenReturn(5L);

        mockMvc.perform(get("/api/scans/count"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalScans").value(5));

        verify(scanService).getTotalScans();
    }

    @Test
    void emptyScanListShouldReturn200() throws Exception {
        when(scanService.getAllScans())
                .thenReturn(List.of());

        mockMvc.perform(get("/api/scans"))
                .andExpect(status().isOk())
                .andExpect(content().json("[]"));
    }

    @Test
    void unknownScanShouldReturn404() throws Exception {
        when(scanService.getScanById(999L))
                .thenReturn(Optional.empty());

        mockMvc.perform(get("/api/scans/999"))
                .andExpect(status().isNotFound());
    }
}
