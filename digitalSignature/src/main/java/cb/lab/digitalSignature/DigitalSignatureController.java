package cb.lab.digitalSignature;

import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequiredArgsConstructor
public class DigitalSignatureController {
    private final DigitalSignatureService digitalSignatureService;
    @PostMapping(value = "/createCertificate", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> createCertificate (
            @RequestParam("documentFile") MultipartFile documentFile,
            @RequestParam("privateKeyFile (PKCS8Encoded)") MultipartFile privateKeyFile,
            @RequestParam("AuthorName") String name,
            @RequestParam("use weak hash?") boolean weakFlag
            ) {
        if (documentFile.isEmpty() || privateKeyFile.isEmpty()) {
            return ResponseEntity.badRequest().body("проверьте документы");
        }

        try {
            return ResponseEntity.ok()
                    .header("Content-Disposition", "attachment; filename=" + documentFile.getOriginalFilename()+ ".sig")
                    .contentType(MediaType.TEXT_PLAIN)
                    .body(
                            digitalSignatureService.makeCertificate(
                                    digitalSignatureService.getDocumentHash(documentFile, weakFlag),
                                    digitalSignatureService.parsePrivateKey(privateKeyFile),
                                    name,
                                    weakFlag
                            )
                    );
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(e.getMessage());
        }
    }

    @PostMapping(value = "checkSignature", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> checkSignature(
            @RequestParam("documentFile") MultipartFile documentFile,
            @RequestParam("base64signature") String base64signature,
            @RequestParam("publicKeyFile (X509Encoded)") MultipartFile publicKeyFile,
            @RequestParam("weak hash was used?") boolean weakFlag
    ) {
        if (documentFile.isEmpty() || publicKeyFile.isEmpty()) {
            return ResponseEntity.badRequest().body("проверьте документы");
        }

        try {
            if (!digitalSignatureService.checkFingerprint (
                    digitalSignatureService.getDocumentHash(documentFile,weakFlag),
                    base64signature,
                    digitalSignatureService.parsePublicKey(publicKeyFile)
                )
            ) {
                return ResponseEntity.badRequest().body("хэши не сошлись, перепроверьте данные/обратитесь к владельцу");
            }
            return ResponseEntity.ok().body("хэши сошлись, документ оригинальный, наверное ))");
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(e.getMessage());
        }
    }
}
