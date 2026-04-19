"""Geo-aware personality selection for response variation.

When the operator enables ``geo.vary_responses``, the engine picks a
"server personality" based on the attacker's origin country. The personality
controls company name, locale hints, and file names the attacker sees. This
powers the research question: *do attackers modify their behavior based on
the perceived origin/type of the server?*
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Personality:
    """A server personality presented to attackers based on origin."""

    key: str
    company: str
    locale: str
    domain: str
    sample_file_names: tuple[str, ...] = field(default_factory=tuple)
    welcome_banner: str = ""
    language_hint: str = "en"


_DEFAULT = Personality(
    key="us_startup",
    company="TechNova Inc.",
    locale="en-US",
    domain="technova.io",
    sample_file_names=(
        "Q1_revenue.xlsx",
        "employee_list_2026.csv",
        "internal_passwords.txt",
        "roadmap_q2.pdf",
        "aws_keys.env",
    ),
    welcome_banner="Welcome to TechNova Internal Server",
    language_hint="en",
)


_PERSONALITIES: dict[str, Personality] = {
    "default": _DEFAULT,
    "US": _DEFAULT,
    "RU": Personality(
        key="russian_company",
        company='ООО "ТехноГрупп"',
        locale="ru-RU",
        domain="technogroup.ru",
        sample_file_names=(
            "отчет_2026.xlsx",
            "сотрудники.csv",
            "пароли.txt",
            "финансы_Q1.xlsx",
            "backup_db.sql.gz",
        ),
        welcome_banner='Добро пожаловать на внутренний сервер ТехноГрупп',
        language_hint="ru",
    ),
    "CN": Personality(
        key="chinese_enterprise",
        company="华信科技有限公司",
        locale="zh-CN",
        domain="huaxin.com.cn",
        sample_file_names=(
            "财务报表.xlsx",
            "员工名单.csv",
            "密码.txt",
            "季度报告.pdf",
            "数据库备份.sql.gz",
        ),
        welcome_banner="欢迎访问华信科技内部服务器",
        language_hint="zh",
    ),
    "DE": Personality(
        key="german_industrial",
        company="Müller Maschinenbau GmbH",
        locale="de-DE",
        domain="mueller-maschinen.de",
        sample_file_names=(
            "Jahresbericht_2026.xlsx",
            "Mitarbeiterliste.csv",
            "Passwortliste.txt",
            "Konstruktionszeichnungen.zip",
            "Finanzen_Q1.xlsx",
        ),
        welcome_banner="Willkommen am Müller Maschinenbau-Server",
        language_hint="de",
    ),
    "BR": Personality(
        key="brazilian_retail",
        company="LojaSul Comércio Ltda.",
        locale="pt-BR",
        domain="lojasul.com.br",
        sample_file_names=(
            "relatorio_Q1.xlsx",
            "funcionarios.csv",
            "senhas.txt",
            "faturamento.pdf",
            "estoque_2026.xlsx",
        ),
        welcome_banner="Bem-vindo ao servidor interno LojaSul",
        language_hint="pt",
    ),
    "IN": Personality(
        key="indian_it_services",
        company="Bharat Infotech Pvt. Ltd.",
        locale="en-IN",
        domain="bharatinfotech.in",
        sample_file_names=(
            "payroll_april.xlsx",
            "client_list.csv",
            "passwords.txt",
            "project_report.pdf",
            "backup.sql.gz",
        ),
        welcome_banner="Welcome to Bharat Infotech internal server",
        language_hint="en",
    ),
    "JP": Personality(
        key="japanese_enterprise",
        company="株式会社テクノソフト",
        locale="ja-JP",
        domain="technosoft.co.jp",
        sample_file_names=(
            "決算報告.xlsx",
            "従業員名簿.csv",
            "パスワード.txt",
            "年次報告書.pdf",
            "バックアップ.sql.gz",
        ),
        welcome_banner="テクノソフト内部サーバーへようこそ",
        language_hint="ja",
    ),
    "FR": Personality(
        key="french_startup",
        company="InnoSoft SARL",
        locale="fr-FR",
        domain="innosoft.fr",
        sample_file_names=(
            "rapport_Q1.xlsx",
            "liste_employes.csv",
            "mots_de_passe.txt",
            "finances_2026.pdf",
        ),
        welcome_banner="Bienvenue sur le serveur interne InnoSoft",
        language_hint="fr",
    ),
}


class GeoPersonalitySelector:
    """Select a personality for a given attacker country code."""

    def __init__(self, *, enabled: bool = True) -> None:
        """Initialize the geo-personality selector with country-to-persona mappings."""
        self.enabled = enabled

    def for_country(self, country_code: str) -> Personality:
        """Return the personality for an ISO country code, or the default."""
        if not self.enabled:
            return _DEFAULT
        if not country_code:
            return _DEFAULT
        return _PERSONALITIES.get(country_code.upper(), _DEFAULT)

    @staticmethod
    def known_codes() -> list[str]:
        """Return every country code with a custom personality."""
        return [k for k in _PERSONALITIES if k not in {"default"}]
