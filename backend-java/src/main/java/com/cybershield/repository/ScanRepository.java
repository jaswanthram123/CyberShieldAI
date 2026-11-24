
package com.cybershield.repository;

import com.cybershield.entity.Scan;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface ScanRepository extends JpaRepository<Scan, Long> {

    List<Scan> findAllByOrderByCreatedAtDesc();

}
