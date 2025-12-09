"""
Описание проекта:
Простой архиватор RAR 5.0, реализованный на Python 3.x. Поддерживает только режим store (без сжатия),
что обеспечивает юридическую безопасность, так как не использует патентованные алгоритмы RAR 5 (RangeCoder, специфический LZ-77).
Архивы совместимы с официальным unrar 5.x и выше. Проект не имеет внешних зависимостей, кроме стандартной библиотеки Python.

Зависимости:
- Python 3.10+ (стандартная библиотека: struct, pathlib, zlib, os, sys, logging)

Лицензия:
MIT License. Проект распространяется свободно, без гарантий.

Контакты:
Для вопросов или вклада: создайте issue на GitHub (предполагаемый репозиторий).

Примеры использования:
- Создание архива: python rar.py a archive.rar file1.txt folder/
- Архив будет содержать file1.txt и все файлы из folder/ с сохранением структуры.

Подробный алгоритм работы:
1. Парсинг аргументов командной строки: команда 'a' для добавления файлов/папок в архив.
2. Сбор списка файлов и директорий: рекурсивный обход директорий для включения всех вложенных файлов и поддиректорий.
3. Формирование структуры архива RAR 5.0:
   - Запись сигнатуры архива (8 байт).
   - Запись главного заголовка архива (Main Archive Header) с флагами и CRC.
   - Для каждой директории: запись заголовка директории (File Header с флагом директории, без данных).
   - Для каждого файла: запись заголовка файла (File Header) с метаданными, затем данные файла в режиме store.
   - Запись заголовка конца архива (End of Archive Header).
4. Вычисление CRC32 для заголовков и данных файлов.
5. Использование vint (variable length integer) для кодирования размеров и других значений.
6. Поддержка относительных путей для имен файлов/директорий в архиве.

Обработка ошибок:
- Кастомные исключения для различных типов ошибок (InvalidPathError, FileReadError, RarCreationError).
- Логирование ошибок в stderr с уровнями ERROR и WARNING.
- Валидация путей и размеров файлов.
"""

from __future__ import annotations

# Standard library imports
import logging
import os
import struct
import sys
import zlib
from typing import IO

# Third-party imports (none)
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

import pathlib

# Настройка логирования для обработки ошибок
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")


class RarError(Exception):
    """Базовое исключение для ошибок архиватора RAR."""

    def __init__(self, message: str = "Ошибка в архиваторе RAR") -> None:
        super().__init__(message)


class InvalidPathError(RarError):
    """Исключение для недействительных путей."""

    def __init__(self, path: pathlib.Path, message: str | None = None) -> None:
        if message is None:
            message = f"Недействительный или несуществующий путь: {path}"
        super().__init__(message)
        self.path: pathlib.Path = path


class FileReadError(RarError):
    """Исключение для ошибок чтения файлов."""

    def __init__(self, path: pathlib.Path, message: str | None = None) -> None:
        if message is None:
            message = f"Ошибка чтения файла: {path}"
        super().__init__(message)
        self.path: pathlib.Path = path


class RarCreationError(RarError):
    """Исключение для ошибок создания архива."""

    def __init__(self, archive_path: pathlib.Path, message: str | None = None) -> None:
        if message is None:
            message = f"Ошибка создания архива: {archive_path}"
        super().__init__(message)
        self.archive_path: pathlib.Path = archive_path


class RarWriter:
    """
    Класс для создания RAR 5.0 архивов в режиме store.
    Инкапсулирует логику записи заголовков и данных.
    """

    def __init__(self, archive_path: pathlib.Path) -> None:
        self.archive_path: pathlib.Path = archive_path
        self.file: IO[bytes] | None = None

    def __enter__(self) -> "RarWriter":
        self.file = self.archive_path.open("wb")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        if self.file:
            self.file.close()  # type: ignore

    def write_signature(self) -> None:
        """Записывает сигнатуру RAR 5.0."""
        assert self.file is not None
        self.file.write(b"Rar!\x1a\x07\x01\x00")  # type: ignore

    def write_main_header(self) -> None:
        """Записывает главный заголовок архива."""
        assert self.file is not None
        header_data = bytes([1, 0, 0])  # Тип, флаги, флаги архива
        header_size_vint = encode_vint(len(header_data))  # type: ignore
        crc_data = header_size_vint + header_data
        header_crc = compute_crc32(crc_data)
        write_uint32(self.file, header_crc)  # type: ignore
        self.file.write(header_size_vint)  # type: ignore
        self.file.write(header_data)  # type: ignore

    def build_header(
        self,
        header_type: int,  # Тип заголовка: 1 - Main, 2 - File/Dir, 5 - End
        flags: int,  # Флаги заголовка: 0x01 - extra area, 0x02 - data area
        data_size: int,  # Размер области данных (packed size для файлов)
        file_flags: int,  # Флаги файла: 0x01 - dir, 0x02 - mtime, 0x04 - CRC
        unpacked_size: int,  # Размер распакованных данных
        attributes: int,  # Атрибуты файла (0 для простоты)
        mtime: int,  # Время модификации (Unix timestamp)
        crc: int,  # CRC32 данных (0 для директорий)
        compression: int,  # Метод сжатия: 0 - store (без сжатия)
        host_os: int,  # ОС создания: 0 - Windows
        name_len: int,  # Длина имени файла
        name: bytes,  # Имя файла в UTF-8
        extra_data: bytes = b"",  # Extra area data
    ) -> None:
        """Строит и записывает заголовок файла или директории по RAR 5.0 спецификации."""
        if extra_data:
            flags |= 0x01  # extra area present
        header_parts = [
            bytes([header_type]),  # Тип заголовка (1 байт)
            bytes([flags]),  # Флаги (1 байт)
        ]
        if flags & 0x01:  # Extra area present
            header_parts.append(
                encode_vint(len(extra_data))
            )  # Размер extra area (vint)
        if flags & 0x02:  # Data area present
            header_parts.append(encode_vint(data_size))  # Размер данных (vint)
        header_parts.extend(
            [
                bytes([file_flags]),  # Флаги файла (1 байт)
                encode_vint(unpacked_size),  # Размер распакованный (vint)
                bytes([attributes]),  # Атрибуты (1 байт)
                struct.pack("<I", mtime),  # Время модификации (4 байта, little-endian)
                struct.pack("<I", crc),  # CRC32 (4 байта, little-endian)
                bytes([compression]),  # Метод сжатия (1 байт)
                bytes([host_os]),  # ОС (1 байт)
                encode_vint(name_len),  # Длина имени (vint)
                name,  # Имя файла (байты)
            ]
        )
        if extra_data:
            header_parts.append(extra_data)  # Extra area
        header_data = b"".join(header_parts)
        header_size_vint = encode_vint(len(header_data))  # type: ignore
        crc_data = header_size_vint + header_data
        header_crc = compute_crc32(crc_data)
        write_uint32(self.file, header_crc)  # type: ignore
        self.file.write(header_size_vint)  # type: ignore
        self.file.write(header_data)  # type: ignore

    def write_file_header(
        self, p: pathlib.Path, rel_name: str, password: str | None = None
    ) -> None:
        """Записывает заголовок файла."""
        data = p.read_bytes()  # Читаем байты файла
        original_size = len(data)
        data_crc = compute_crc32(data)  # CRC для оригинальных данных
        extra_data = b""
        if password:
            data, extra_data = encrypt_file_data(data, password)
        unpacked_size = len(data)  # type: ignore
        packed_size = unpacked_size
        mtime = int(p.stat().st_mtime)  # type: ignore
        name_utf8 = rel_name.encode("utf-8")
        name_len = len(name_utf8)  # type: ignore

        file_flags = 0x06  # mtime + CRC

        self.build_header(
            header_type=2,
            flags=0x02,
            data_size=packed_size,
            file_flags=file_flags,
            unpacked_size=original_size,  # Оригинальный размер
            attributes=0,
            mtime=mtime,
            crc=data_crc,
            compression=0,
            host_os=0,
            name_len=name_len,
            name=name_utf8,
            extra_data=extra_data,
        )
        self.file.write(data)  # type: ignore

    def write_dir_header(self, p: pathlib.Path, rel_name: str) -> None:
        """Записывает заголовок директории."""
        mtime = int(p.stat().st_mtime)  # type: ignore  # Время модификации директории
        name_utf8 = rel_name.encode(
            "utf-8"
        )  # Имя с слэшем для директорий (уже добавлено в create_rar)
        name_len = len(name_utf8)  # type: ignore

        self.build_header(
            header_type=2,  # File header (для директорий тоже)
            flags=0,  # Флаг: нет области данных (no data area)
            data_size=0,  # Директории не имеют packed данных
            file_flags=0x07,  # Флаги: dir (0x01) + mtime (0x02) + CRC (0x04)
            unpacked_size=0,  # Размер распакованный = 0
            attributes=0,
            mtime=mtime,
            crc=0,  # CRC для директорий = 0
            compression=0,
            host_os=0,
            name_len=name_len,
            name=name_utf8,
        )

    def write_end_header(self) -> None:
        """Записывает заголовок конца архива."""
        header_data = bytes(
            [5, 0, 0]
        )  # Тип: 5 (End of Archive), флаги: 0, флаги конца: 0
        header_size_vint = encode_vint(len(header_data))  # type: ignore  # Размер заголовка в vint
        crc_data = header_size_vint + header_data  # Данные для CRC: size + header
        header_crc = compute_crc32(crc_data)  # CRC32 заголовка
        write_uint32(self.file, header_crc)  # type: ignore  # Записываем CRC (4 байта)
        self.file.write(header_size_vint)  # type: ignore  # Записываем размер заголовка
        self.file.write(header_data)  # type: ignore  # Записываем данные заголовка


def encode_vint(value: int) -> bytes:
    """
    Кодирует целое число в vint (variable length integer) по RAR 5.0 спецификации.
    Vint использует 7 бит на байт для данных, старший бит - флаг продолжения.
    Максимум 10 байт для 64-битных чисел.

    Пример:
        >>> encode_vint(300)
        b'\\xac\\x02'

    Возвращает байты vint.
    """
    result = []
    while True:
        byte = value & 0x7F  # Младшие 7 бит данных
        value >>= 7  # Сдвиг на 7 бит
        if value == 0:
            result.append(byte)  # Последний байт без флага
            break
        else:
            result.append(byte | 0x80)  # Флаг продолжения (старший бит = 1)
    return bytes(result)


def write_uint32(f: IO[bytes], value: int) -> None:
    """Записывает 32-битное беззнаковое целое число в little-endian формате."""
    f.write(struct.pack("<I", value))


def compute_crc32(data: bytes) -> int:
    """Вычисляет CRC32 для данных и возвращает 32-битное значение."""
    return zlib.crc32(data) & 0xFFFFFFFF


def derive_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    """Генерирует ключ AES-256 из пароля с PBKDF2."""
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library required for encryption")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Шифрует данные AES-256 CBC с PKCS7 padding."""
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library required for encryption")
    from cryptography.hazmat.primitives import padding

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()  # 128 бит = 16 байт
    padded_data = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted


def encrypt_file_data(data: bytes, password: str) -> tuple[bytes, bytes]:
    """Шифрует данные файла и возвращает (encrypted_data, extra_record)."""
    salt = os.urandom(16)
    iv = os.urandom(16)
    kdf_count = 19  # 2^19 = 524288 iterations
    iterations = 1 << kdf_count
    key = derive_key(password, salt, iterations)
    extra_data = create_file_encryption_record(key, salt, iv, kdf_count)
    encrypted_data = encrypt_data(data, key, iv)
    return encrypted_data, extra_data


def create_file_encryption_record(
    key: bytes, salt: bytes, iv: bytes, kdf_count: int
) -> bytes:
    """Создаёт file encryption record для extra area по RAR 5.0."""
    # Check value: первые 8 байт PBKDF2, 4 байта CRC32
    check_value = key[:8] + struct.pack("<I", compute_crc32(key[:8]))
    # Record data: type + version + flags + kdf + salt + iv + check
    record_data = (
        encode_vint(0x01)  # Type
        + bytes([0])  # Version
        + encode_vint(0x0001)  # Flags: password check data is present
        + bytes([kdf_count])  # KDF count
        + salt
        + iv
        + check_value
    )
    size = encode_vint(len(record_data))
    return size + record_data


def get_files_and_dirs(paths: list[pathlib.Path]) -> list[pathlib.Path]:
    """
    Собирает список всех файлов и директорий из заданных путей.
    Для директорий рекурсивно добавляет все поддиректории и файлы.
    Возвращает отсортированный список pathlib.Path объектов.
    """
    result: list[pathlib.Path] = []
    base = pathlib.Path.cwd()
    for p in paths:
        try:
            resolved = p.resolve()  # Получаем абсолютный путь для корректности
            # Безопасность: запретить path traversal
            if not resolved.is_relative_to(base):
                raise InvalidPathError(
                    p, f"Путь {p} находится вне базовой директории {base}"
                )
            if p.is_file():
                result.append(p)  # type: ignore
            elif p.is_dir():
                # Добавляем директорию в список
                result.append(p)  # type: ignore
                # Рекурсивно добавляем поддиректории и файлы с помощью os.walk
                for root, dirs, files in os.walk(p):  # type: ignore
                    root_p = pathlib.Path(root)
                    for d in sorted(dirs):  # type: ignore
                        result.append(root_p / d)  # type: ignore
                    for f in sorted(files):  # type: ignore
                        result.append(root_p / f)  # type: ignore
        except (OSError, ValueError) as e:
            logging.error(f"Ошибка при обработке пути {p}: {e}")
            raise FileReadError(p, f"Не удалось обработать путь {p}: {e}") from e
    return sorted(result)


def create_rar(
    archive_path: pathlib.Path, paths: list[pathlib.Path], password: str | None = None
) -> None:
    """
    Создаёт RAR 5.0 архив в режиме store.
    Принимает путь к архиву, список путей и опциональный пароль для шифрования.

    Raises:
        RarCreationError: Если ошибка при создании архива.
        InvalidPathError: Если пути некорректны.
        FileReadError: Если ошибка чтения файлов.
    """
    try:
        files_and_dirs = get_files_and_dirs(paths)
        base = pathlib.Path.cwd()

        with RarWriter(archive_path) as writer:
            writer.write_signature()
            writer.write_main_header()

            for p in files_and_dirs:
                try:
                    rel_name = p.resolve().relative_to(base).as_posix()
                    if p.is_dir():
                        rel_name += "/"
                        writer.write_dir_header(p, rel_name)
                    else:
                        writer.write_file_header(p, rel_name, password)
                except ValueError as e:
                    logging.warning(f"Пропуск {p}: {e}")
                    continue  # Пропускаем проблемные файлы

            writer.write_end_header()
    except (InvalidPathError, FileReadError):
        raise  # Перебрасываем кастомные исключения
    except Exception as e:
        logging.error(f"Неожиданная ошибка при создании архива: {e}")
        raise RarCreationError(
            archive_path, f"Не удалось создать архив {archive_path}: {e}"
        ) from e


def parse_command_line_args() -> tuple[
    pathlib.Path, list[pathlib.Path], bool, str | None
]:
    """Парсит аргументы командной строки и возвращает путь архива, список путей, флаг verbose и пароль."""
    import argparse

    parser = argparse.ArgumentParser(description="Простой архиватор RAR 5.0")
    parser.add_argument("command", choices=["a"], help="Команда: a для добавления")
    parser.add_argument("archive", help="Путь к архиву")
    parser.add_argument("files", nargs="+", help="Файлы и директории для архивации")
    parser.add_argument(
        "--verbose", action="store_true", help="Выводить прогресс и время"
    )
    parser.add_argument("--password", help="Пароль для шифрования (запрос в unrar)")

    args = parser.parse_args()  # type: ignore

    archive_path = pathlib.Path(args.archive)
    if args.password and not CRYPTOGRAPHY_AVAILABLE:
        print("Ошибка: Для шифрования установите 'pip install cryptography'")
        sys.exit(1)

    paths: list[pathlib.Path] = []
    for arg in args.files:  # type: ignore
        p = pathlib.Path(arg)
        if not p.exists():
            print(f"Ошибка: Путь {p} не существует.")
            sys.exit(1)
        paths.append(p)  # type: ignore
    return archive_path, paths, args.verbose, args.password  # type: ignore


def handle_archive_overwrite(archive_path: pathlib.Path) -> None:
    """Обрабатывает подтверждение перезаписи существующего архива."""
    try:
        if archive_path.exists():
            try:
                response = (
                    input(f"Архив {archive_path} уже существует. Перезаписать? (y/n): ")
                    .strip()
                    .lower()
                )
                if response != "y":
                    print("Операция отменена.")
                    sys.exit(0)
            except EOFError:
                print("Ввод недоступен. Перезапись отменена.")
                sys.exit(0)
    except KeyboardInterrupt:
        print("\nОперация прервана пользователем.")
        sys.exit(1)
    except Exception as e:
        print(f"Неожиданная ошибка при проверке архива: {e}")
        sys.exit(1)


def main() -> None:
    """Основная функция для запуска архиватора из командной строки."""
    archive_path, paths, verbose, password = parse_command_line_args()
    handle_archive_overwrite(archive_path)

    import time

    start_time = time.time()

    try:
        create_rar(archive_path, paths, password)
        elapsed = time.time() - start_time
        print(f"Архив {archive_path} создан успешно.")
        if verbose:
            print(f"Время выполнения: {elapsed:.2f} секунд.")
    except (InvalidPathError, FileReadError, RarCreationError) as e:
        print(f"Ошибка: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nОперация прервана пользователем.")
        sys.exit(1)


if __name__ == "__main__":
    main()
