<?php
use Hardened\Sanitizers\HtmlSanitizer;

require __DIR__ . '/vendor/autoload.php';

class HtmlSanitizerBenchmark
{
    private $htmlSanitizer;
    private $ezyangHtmlPurifier;

    private $payload10kb;
    public function __construct() {
         $this->ezyangHtmlPurifier = new HTMLPurifier(HTMLPurifier_Config::createDefault());
         $this->htmlSanitizer = HtmlSanitizer::default();
         $this->payload10kb = $this->payload(10 * 1024);
    }

    public function payload(int $targetSize): String {
        $buffer = '<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><title>Benchmark HTML Purifier</title></head><body>';
        while (strlen($buffer) < $targetSize) {
            $buffer .= '<div class="benchmark-item">Lorem ipsum dolor sit amet, <a href="javascript:alert(document.cookie)">consectetur</a> adipiscing elit. Quisque at.</div>';
        }
        $buffer .= '</body></html>';
        return $buffer;
    }

    /**
     * @Revs(10000)
     */
    public function benchHtmlSanitizer10kb(): void
    {
         $this->htmlSanitizer->clean($this->payload10kb);
    }

    /**
     * @Revs(10000)
     */
    public function benchEzyangHtmlPurifier10kb(): void
    {
        $this->ezyangHtmlPurifier->purify($this->payload10kb);
    }

    /**
     * @Revs(10000)
     */
    public function benchTidy10kb(): void
    {
        $tidy = new tidy;
        $tidy->parseString($this->payload10kb, [], 'utf8');
        $tidy->cleanRepair();
    }
}
