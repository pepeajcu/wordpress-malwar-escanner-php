<?php

declare(strict_types=1);

interface AIProviderInterface
{
    public function name(): string;

    /**
     * @param string $filename Nombre/ruta relativa del archivo, solo como contexto.
     * @param string $snippet Fragmento del contenido del archivo (ya truncado por el llamador).
     * @param string[] $heuristicReasons Motivos por los que capas anteriores marcaron el archivo.
     * @return array{verdict:string, confidence:float, explanation:string}|null
     *         verdict: "malicious" | "suspicious" | "clean" | "unknown". null si la llamada falló.
     */
    public function analyze(string $filename, string $snippet, array $heuristicReasons): ?array;
}
