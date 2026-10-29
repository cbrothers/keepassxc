/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "TestSharing.h"

#include <QSignalSpy>
#include <QTest>
#include <QXmlStreamReader>

#include "core/Database.h"
#include "core/Group.h"
#include "crypto/Crypto.h"
#include "crypto/Random.h"
#include "keeshare/KeeShare.h"
#include "keeshare/KeeShareSettings.h"
#include "keeshare/ShareObserver.h"

#include <botan/rsa.h>

QTEST_GUILESS_MAIN(TestSharing)

Q_DECLARE_METATYPE(KeeShareSettings::Type)
Q_DECLARE_METATYPE(KeeShareSettings::Key)
Q_DECLARE_METATYPE(KeeShareSettings::Certificate)

void TestSharing::initTestCase()
{
    QVERIFY(Crypto::init());
    QLocale::setDefault(QLocale::c());
    KeeShare::init(this);
}

void TestSharing::cleanup()
{
    KeeShareSettings::Reference::resetUncProbeFunc();
    KeeShare::setActive({});
}

void TestSharing::testNullObjects()
{
    const QString empty;
    QXmlStreamReader reader(empty);

    const auto nullKey = KeeShareSettings::Key();
    QVERIFY(nullKey.isNull());
    const auto xmlKey = KeeShareSettings::Key::deserialize(reader);
    QVERIFY(xmlKey.isNull());

    const auto certificate = KeeShareSettings::Certificate();
    QVERIFY(certificate.isNull());
    const auto xmlCertificate = KeeShareSettings::Certificate::deserialize(reader);
    QVERIFY(xmlCertificate.isNull());

    const auto own = KeeShareSettings::Own();
    QVERIFY(own.isNull());
    const auto xmlOwn = KeeShareSettings::Own::deserialize(empty);
    QVERIFY(xmlOwn.isNull());

    const auto active = KeeShareSettings::Active();
    QVERIFY(active.isNull());
    const auto xmlActive = KeeShareSettings::Active::deserialize(empty);
    QVERIFY(xmlActive.isNull());

    const auto reference = KeeShareSettings::Reference();
    QVERIFY(reference.isNull());
    const auto xmlReference = KeeShareSettings::Reference::deserialize(empty);
    QVERIFY(xmlReference.isNull());
}

void TestSharing::testKeySerialization()
{
    auto key = stubkey();
    KeeShareSettings::Key original;
    original.key = key;

    QString buffer;
    QXmlStreamWriter writer(&buffer);
    writer.writeStartDocument();
    writer.writeStartElement("Key");
    KeeShareSettings::Key::serialize(writer, original);
    writer.writeEndElement();
    writer.writeEndDocument();
    QXmlStreamReader reader(buffer);
    reader.readNextStartElement();
    QVERIFY(reader.name().toString() == "Key");
    KeeShareSettings::Key restored = KeeShareSettings::Key::deserialize(reader);

    QCOMPARE(restored.key->private_key_bits(), original.key->private_key_bits());
    QCOMPARE(restored.key->algo_name(), original.key->algo_name());
}

void TestSharing::testReferenceSerialization()
{
    QFETCH(QString, password);
    QFETCH(QString, path);
    QFETCH(QUuid, uuid);
    QFETCH(int, type);
    QFETCH(int, uncTimeout);
    KeeShareSettings::Reference original;
    original.password = password;
    original.path = path;
    original.uuid = uuid;
    original.type = static_cast<KeeShareSettings::Type>(type);
    original.uncTimeout = uncTimeout;

    const QString serialized = KeeShareSettings::Reference::serialize(original);
    const bool expectUncTimeoutElement = original.uncTimeout != KeeShareSettings::Reference::DefaultUncTimeout;
    QCOMPARE(serialized.contains("<UncTimeout>"), expectUncTimeoutElement);

    const KeeShareSettings::Reference restored = KeeShareSettings::Reference::deserialize(serialized);

    QCOMPARE(restored.password, original.password);
    QCOMPARE(restored.path, original.path);
    QCOMPARE(restored.uuid, original.uuid);
    QCOMPARE(int(restored.type), int(original.type));
    QCOMPARE(restored.uncTimeout, original.uncTimeout);
}

void TestSharing::testReferenceSerialization_data()
{
    QTest::addColumn<QString>("password");
    QTest::addColumn<QString>("path");
    QTest::addColumn<QUuid>("uuid");
    QTest::addColumn<int>("type");
    QTest::addColumn<int>("uncTimeout");
    QTest::newRow("1") << "Password" << "/some/path" << QUuid::createUuid() << int(KeeShareSettings::Inactive) << 3;
    QTest::newRow("2") << "" << "" << QUuid() << int(KeeShareSettings::SynchronizeWith) << 5;
    QTest::newRow("3") << "" << "\\\\server\\share\\file.kdbx" << QUuid() << int(KeeShareSettings::ExportTo) << 10;
    QTest::newRow("4") << "" << "\\\\server\\share\\default.kdbx" << QUuid() << int(KeeShareSettings::ImportFrom) << 3;
}

void TestSharing::testReferenceInvalidUncTimeoutDeserialization()
{
    KeeShareSettings::Reference base;
    base.path = "\\\\server\\share\\file.kdbx";
    base.type = KeeShareSettings::ImportFrom;
    base.uncTimeout = 10;
    const QString validXml = KeeShareSettings::Reference::serialize(base);

    QString zeroXml = validXml;
    zeroXml.replace("<UncTimeout>10</UncTimeout>", "<UncTimeout>0</UncTimeout>");
    QCOMPARE(KeeShareSettings::Reference::deserialize(zeroXml).uncTimeout,
             KeeShareSettings::Reference::DefaultUncTimeout);

    QString tooLargeXml = validXml;
    tooLargeXml.replace("<UncTimeout>10</UncTimeout>", "<UncTimeout>999</UncTimeout>");
    QCOMPARE(KeeShareSettings::Reference::deserialize(tooLargeXml).uncTimeout,
             KeeShareSettings::Reference::DefaultUncTimeout);

    QString nonNumericXml = validXml;
    nonNumericXml.replace("<UncTimeout>10</UncTimeout>", "<UncTimeout>invalid</UncTimeout>");
    QCOMPARE(KeeShareSettings::Reference::deserialize(nonNumericXml).uncTimeout,
             KeeShareSettings::Reference::DefaultUncTimeout);
}

void TestSharing::testUncPathDetection()
{
    QVERIFY(KeeShareSettings::Reference::isUncPath("\\\\server\\share\\vault.kdbx"));
    QCOMPARE(KeeShareSettings::Reference::extractUncHost("\\\\server\\share\\vault.kdbx"), QString("server"));

#ifdef Q_OS_WIN
    QVERIFY(KeeShareSettings::Reference::isUncPath("//10.10.1.3/share/vault.kdbx.share"));
    QCOMPARE(KeeShareSettings::Reference::extractUncHost("//10.10.1.3/share/vault.kdbx.share"), QString("10.10.1.3"));
#else
    QVERIFY(!KeeShareSettings::Reference::isUncPath("//10.10.1.3/share/vault.kdbx.share"));
#endif

    QVERIFY(KeeShareSettings::Reference::isUncPath("\\\\?\\UNC\\fileserver.local\\share\\vault.kdbx"));
    QCOMPARE(KeeShareSettings::Reference::extractUncHost("\\\\?\\UNC\\fileserver.local\\share\\vault.kdbx"),
             QString("fileserver.local"));

    QVERIFY(!KeeShareSettings::Reference::isUncPath("C:\\Users\\user\\vault.kdbx"));
    QVERIFY(!KeeShareSettings::Reference::isUncPath("/home/user/vault.kdbx"));
    QVERIFY(!KeeShareSettings::Reference::isUncPath("\\\\?\\C:\\Users\\user\\vault.kdbx"));
    QVERIFY(!KeeShareSettings::Reference::isUncPath("relative/path/vault.kdbx"));
}

void TestSharing::testUncProbeClamping()
{
    QHash<QString, int> probeCounts;
    QList<int> recordedTimeouts;
    KeeShareSettings::Reference::setUncProbeFunc([&](const QString& host, int timeoutMs) {
        probeCounts[host.toLower()]++;
        recordedTimeouts.append(timeoutMs);
        return false;
    });

    // Verify timeout clamping and host extraction through Reference::isUncPathActive
    QVERIFY(!KeeShareSettings::Reference::isUncPathActive("\\\\offline-host\\share\\test.kdbx", 4));
    QCOMPARE(probeCounts.value("offline-host"), 1);
    QCOMPARE(recordedTimeouts.last(), 4000);

    // Out-of-range timeouts are clamped to [MinUncTimeout, MaxUncTimeout]
    QVERIFY(!KeeShareSettings::Reference::isUncPathActive("\\\\offline-host\\share\\test.kdbx", 0));
    QCOMPARE(recordedTimeouts.last(), KeeShareSettings::Reference::MinUncTimeout * 1000);
    QVERIFY(!KeeShareSettings::Reference::isUncPathActive("\\\\offline-host\\share\\test.kdbx", 999));
    QCOMPARE(recordedTimeouts.last(), KeeShareSettings::Reference::MaxUncTimeout * 1000);

    // Local paths do not invoke the UNC probe
    const int countBeforeLocal = probeCounts.value("offline-host");
    QVERIFY(KeeShareSettings::Reference::isUncPathActive("/local/path/test.kdbx", 3));
    QCOMPARE(probeCounts.value("offline-host"), countBeforeLocal);

    // Verify reachable UNC host returns true
    KeeShareSettings::Reference::setUncProbeFunc([&](const QString& host, int) {
        return host.compare("online-host", Qt::CaseInsensitive) == 0;
    });
    QVERIFY(KeeShareSettings::Reference::isUncPathActive("\\\\online-host\\share\\test.kdbx", 3));
    QVERIFY(!KeeShareSettings::Reference::isUncPathActive("\\\\offline-host\\share\\test.kdbx", 3));
}

void TestSharing::testShareObserverHostCachingAndSkip()
{
    KeeShareSettings::Active active;
    active.in = true;
    active.out = true;
    KeeShare::setActive(active);

    auto db = QSharedPointer<Database>::create();
    auto* group1 = new Group();
    group1->setName("Share 1");
    group1->setParent(db->rootGroup());
    KeeShareSettings::Reference ref1;
    ref1.type = KeeShareSettings::SynchronizeWith;
    ref1.path = "\\\\offline-host\\share1\\vault1.kdbx";
    ref1.uncTimeout = 3;
    KeeShare::setReferenceTo(group1, ref1);

    auto* group2 = new Group();
    group2->setName("Share 2");
    group2->setParent(db->rootGroup());
    KeeShareSettings::Reference ref2;
    ref2.type = KeeShareSettings::SynchronizeWith;
    ref2.path = "\\\\offline-host\\share2\\vault2.kdbx";
    ref2.uncTimeout = 12;
    KeeShare::setReferenceTo(group2, ref2);

    auto* group3 = new Group();
    group3->setName("Share 3");
    group3->setParent(db->rootGroup());
    KeeShareSettings::Reference ref3;
    ref3.type = KeeShareSettings::ImportFrom;
    ref3.path = "\\\\second-host\\share\\vault3.kdbx";
    ref3.uncTimeout = 5;
    KeeShare::setReferenceTo(group3, ref3);

    QHash<QString, int> probeCounts;
    QHash<QString, int> hostTimeouts;
    KeeShareSettings::Reference::setUncProbeFunc([&](const QString& host, int timeoutMs) {
        const QString lowerHost = host.toLower();
        probeCounts[lowerHost]++;
        hostTimeouts[lowerHost] = timeoutMs;
        return false;
    });

    // ShareObserver's constructor invokes handleDatabaseChanged() -> reinitialize() synchronously.
    // Two shares on offline-host (3s and 12s) must probe offline-host only once using max timeout (12s).
    ShareObserver observer(db);
    QCOMPARE(probeCounts.value("offline-host"), 1);
    QCOMPARE(hostTimeouts.value("offline-host"), 12000);
    QCOMPARE(probeCounts.value("second-host"), 1);
    QCOMPARE(hostTimeouts.value("second-host"), 5000);

    // Saving the database must also probe offline-host only once across both exporting groups using max timeout (12s),
    // and emit a single warning message for the pass.
    QSignalSpy messageSpy(&observer, &ShareObserver::sharingMessage);
    probeCounts.clear();
    hostTimeouts.clear();
    emit db->databaseSaved();
    QCOMPARE(probeCounts.value("offline-host"), 1);
    QCOMPARE(hostTimeouts.value("offline-host"), 12000);
    QCOMPARE(messageSpy.count(), 1);
    QCOMPARE(qvariant_cast<MessageWidget::MessageType>(messageSpy.at(0).at(1)), MessageWidget::Warning);
}

void TestSharing::testShareObserverSkippedShareLateOnlineExportWarning()
{
    KeeShareSettings::Active active;
    active.in = true;
    active.out = true;
    KeeShare::setActive(active);

    auto db = QSharedPointer<Database>::create();
    auto* group = new Group();
    group->setName("Sync Share");
    group->setParent(db->rootGroup());
    KeeShareSettings::Reference ref;
    ref.type = KeeShareSettings::SynchronizeWith;
    ref.path = "\\\\flaky-host\\share\\vault.kdbx";
    ref.uncTimeout = 4;
    KeeShare::setReferenceTo(group, ref);

    bool hostOnline = false;
    KeeShareSettings::Reference::setUncProbeFunc([&](const QString&, int) { return hostOnline; });

    // Host is offline at database open, so initial import is skipped.
    ShareObserver observer(db);
    QSignalSpy messageSpy(&observer, &ShareObserver::sharingMessage);

    // Host comes online before save; export must be skipped with a warning rather than overwriting unmerged remote data.
    hostOnline = true;
    emit db->databaseSaved();
    QCOMPARE(messageSpy.count(), 1);
    QVERIFY(messageSpy.at(0).at(0).toString().contains("unreachable on open"));
    QCOMPARE(qvariant_cast<MessageWidget::MessageType>(messageSpy.at(0).at(1)), MessageWidget::Warning);
}

void TestSharing::testSettingsSerialization()
{
    QFETCH(bool, importing);
    QFETCH(bool, exporting);
    QFETCH(KeeShareSettings::Certificate, ownCertificate);
    QFETCH(KeeShareSettings::Key, ownKey);

    KeeShareSettings::Own originalOwn;
    KeeShareSettings::Active originalActive;
    originalActive.in = importing;
    originalActive.out = exporting;
    originalOwn.certificate = ownCertificate;
    originalOwn.key = ownKey;

    const QString serializedActive = KeeShareSettings::Active::serialize(originalActive);
    KeeShareSettings::Active restoredActive = KeeShareSettings::Active::deserialize(serializedActive);

    const QString serializedOwn = KeeShareSettings::Own::serialize(originalOwn);
    KeeShareSettings::Own restoredOwn = KeeShareSettings::Own::deserialize(serializedOwn);

    QCOMPARE(restoredActive.in, importing);
    QCOMPARE(restoredActive.out, exporting);
    if (ownCertificate.key) {
        QCOMPARE(restoredOwn.certificate, ownCertificate);
    }
    if (ownKey.key) {
        QCOMPARE(restoredOwn.key, ownKey);
    }
}

void TestSharing::testSettingsSerialization_data()
{
    auto sshKey0 = stubkey(0);

    KeeShareSettings::Certificate certificate0;
    certificate0.key = sshKey0;
    certificate0.signer = "signer";

    KeeShareSettings::Key key0;
    key0.key = sshKey0;

    QTest::addColumn<bool>("importing");
    QTest::addColumn<bool>("exporting");
    QTest::addColumn<KeeShareSettings::Certificate>("ownCertificate");
    QTest::addColumn<KeeShareSettings::Key>("ownKey");

    QTest::newRow("1") << false << false << KeeShareSettings::Certificate() << KeeShareSettings::Key();
    QTest::newRow("2") << true << false << KeeShareSettings::Certificate() << KeeShareSettings::Key();
    QTest::newRow("3") << true << true << KeeShareSettings::Certificate() << KeeShareSettings::Key();
    QTest::newRow("4") << false << true << certificate0 << key0;
    QTest::newRow("5") << false << false << certificate0 << key0;
}

const QSharedPointer<Botan::RSA_PrivateKey> TestSharing::stubkey(int index)
{
    static QMap<int, QSharedPointer<Botan::RSA_PrivateKey>> keys;
    if (!keys.contains(index)) {
        keys.insert(index,
                    QSharedPointer<Botan::RSA_PrivateKey>(new Botan::RSA_PrivateKey(*randomGen()->getRng(), 2048)));
    }
    return keys[index];
}
