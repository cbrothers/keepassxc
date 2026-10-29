/*
 *  Copyright (C) 2018 KeePassXC Team <team@keepassxc.org>
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

#include "ShareObserver.h"
#include "core/FileWatcher.h"
#include "core/Group.h"
#include "keeshare/KeeShare.h"
#include "keeshare/ShareExport.h"
#include "keeshare/ShareImport.h"

#include <QDir>

namespace
{
    QString resolvePath(const QString& path, QSharedPointer<Database> database)
    {
        if (KeeShareSettings::Reference::isUncPath(path)) {
            return QDir::fromNativeSeparators(path.trimmed());
        }
        const QFileInfo info(database->filePath());
        return info.absoluteDir().absoluteFilePath(path);
    }

    constexpr int FileWatchPeriod = 30;
    constexpr int FileWatchSize = 5;
} // End Namespace

ShareObserver::ShareObserver(QSharedPointer<Database> db, QObject* parent)
    : QObject(parent)
    , m_db(std::move(db))
{
    connect(KeeShare::instance(), &KeeShare::activeChanged, this, &ShareObserver::handleDatabaseChanged);

    connect(m_db.data(), &Database::groupDataChanged, this, &ShareObserver::handleDatabaseChanged);
    connect(m_db.data(), &Database::groupAdded, this, &ShareObserver::handleDatabaseChanged);
    connect(m_db.data(), &Database::groupRemoved, this, &ShareObserver::handleDatabaseChanged);

    connect(m_db.data(), &Database::modified, this, &ShareObserver::handleDatabaseChanged);
    connect(m_db.data(), &Database::databaseSaved, this, &ShareObserver::handleDatabaseSaved);

    handleDatabaseChanged();
}

ShareObserver::~ShareObserver()
{
    m_db->disconnect(this);
}

void ShareObserver::setEnabled(bool enabled)
{
    m_enabled = enabled;
}

void ShareObserver::deinitialize()
{
    m_groupToReference.clear();
    m_shareToGroup.clear();
    m_fileWatchers.clear();
    m_skippedShares.clear();
}

void ShareObserver::reinitialize()
{
    struct ShareEntry
    {
        QPointer<Group> group;
        KeeShareSettings::Reference reference;
        QString resolvedPath;
    };

    QList<ShareEntry> shares;
    for (Group* group : m_db->rootGroup()->groupsRecursive(true)) {
        auto oldReference = m_groupToReference.value(group);
        auto newReference = KeeShare::referenceOf(group);
        if (oldReference == newReference) {
            continue;
        }

        const auto oldResolvedPath = resolvePath(oldReference.path, m_db);
        m_groupToReference.remove(group);
        m_shareToGroup.remove(oldResolvedPath);
        m_fileWatchers.remove(oldResolvedPath);
        m_skippedShares.remove(oldResolvedPath);

        QString newResolvedPath;
        if (newReference.isValid()) {
            m_groupToReference[group] = newReference;
            newResolvedPath = resolvePath(newReference.path, m_db);
            m_shareToGroup[newResolvedPath] = group;
        }

        shares.append({group, newReference, newResolvedPath});
    }

    QHash<QString, int> maxHostTimeout;
    for (const auto& share : shares) {
        if (!share.group || !share.reference.isValid()) {
            continue;
        }
        const QString host = KeeShareSettings::Reference::extractUncHost(share.resolvedPath).toLower();
        if (!host.isEmpty()) {
            maxHostTimeout[host] = qMax(maxHostTimeout.value(host, 0), share.reference.uncTimeout);
        }
    }

    QStringList success;
    QStringList warning;
    QStringList error;
    QMap<QString, QStringList> imported;
    QMap<QString, QStringList> exported;
    QHash<QString, bool> hostCache;
    bool skippedUnreachable = false;

    for (const auto& share : shares) {
        auto group = share.group;
        const auto& reference = share.reference;
        const auto& newResolvedPath = share.resolvedPath;
        // Check group validity, it may have been deleted by a merge action
        if (!group) {
            continue;
        }

        if (!reference.path.isEmpty() && reference.type != KeeShareSettings::Inactive) {
            const QString host = KeeShareSettings::Reference::extractUncHost(newResolvedPath).toLower();
            const int probeTimeout = maxHostTimeout.value(host, reference.uncTimeout);
            if (!isSharePathReachable(newResolvedPath, probeTimeout, hostCache)) {
                qDebug("KeeShare: Network share host not reachable within %d seconds, skipping sync", probeTimeout);
                m_skippedShares.insert(newResolvedPath);
                skippedUnreachable = true;
                continue;
            }
            m_skippedShares.remove(newResolvedPath);
            auto fileWatcher = QSharedPointer<FileWatcher>::create(this);
            connect(fileWatcher.data(), &FileWatcher::fileChanged, this, &ShareObserver::handleFileUpdated);
            fileWatcher->start(newResolvedPath, FileWatchPeriod, FileWatchSize);
            m_fileWatchers.insert(newResolvedPath, fileWatcher);
        }
        if (reference.isExporting()) {
            exported[reference.path] << group->name();
            // export is only on save
        }

        if (reference.isImporting()) {
            imported[reference.path] << group->name();
            // import has to occur immediately
            const auto result = this->importShare(reference.path, &hostCache);
            if (!result.isValid()) {
                // tolerable result - blocked import or missing source
                continue;
            }

            if (result.isError()) {
                error << tr("Import from %1 failed (%2)").arg(result.path).arg(result.message);
            } else if (result.isWarning()) {
                warning << tr("Import from %1 failed (%2)").arg(result.path).arg(result.message);
            } else if (result.isInfo()) {
                success << tr("Import from %1 successful (%2)").arg(result.path).arg(result.message);
            } else {
                success << tr("Imported from %1").arg(result.path);
            }
        }
    }

    if (skippedUnreachable) {
        warning << tr("Network share host unreachable, sync skipped");
    }

    for (auto it = imported.cbegin(); it != imported.cend(); ++it) {
        if (it.value().count() > 1) {
            warning << tr("Multiple import source path to %1 in %2").arg(it.key(), it.value().join(", "));
        }
    }

    for (auto it = exported.cbegin(); it != exported.cend(); ++it) {
        if (it.value().count() > 1) {
            error << tr("Conflicting export target path %1 in %2").arg(it.key(), it.value().join(", "));
        }
    }

    notifyAbout(success, warning, error);
}

void ShareObserver::notifyAbout(const QStringList& success, const QStringList& warning, const QStringList& error)
{
    QStringList messages;
    MessageWidget::MessageType type = MessageWidget::Positive;
    if (!(success.isEmpty() || config()->get(Config::KeeShare_QuietSuccess).toBool())) {
        messages += success;
    }
    if (!warning.isEmpty()) {
        type = MessageWidget::Warning;
        messages += warning;
    }
    if (!error.isEmpty()) {
        type = MessageWidget::Error;
        messages += error;
    }
    if (!messages.isEmpty()) {
        emit sharingMessage(messages.join("\n"), type);
    }
}

void ShareObserver::handleDatabaseChanged()
{
    if (!m_db) {
        Q_ASSERT(m_db);
        return;
    }

    const auto active = KeeShare::active();
    if (!m_enabled || (!active.out && !active.in)) {
        deinitialize();
    } else {
        reinitialize();
    }
}

bool ShareObserver::isSharePathReachable(const QString& resolvedPath,
                                         int uncTimeout,
                                         QHash<QString, bool>& hostCache) const
{
    const QString host = KeeShareSettings::Reference::extractUncHost(resolvedPath).toLower();
    if (host.isEmpty()) {
        return true;
    }
    auto it = hostCache.constFind(host);
    if (it != hostCache.cend()) {
        return it.value();
    }
    const bool reachable = KeeShareSettings::Reference::isUncPathActive(resolvedPath, uncTimeout);
    hostCache.insert(host, reachable);
    return reachable;
}

void ShareObserver::handleFileUpdated(const QString& path)
{
    if (!m_inFileUpdate) {
        QTimer::singleShot(100, this, [this, path] {
            const Result result = importShare(path);
            m_inFileUpdate = false;
            if (!result.isValid()) {
                return;
            }
            QStringList success;
            QStringList warning;
            QStringList error;
            if (result.isError()) {
                error << tr("Import from %1 failed (%2)").arg(result.path, result.message);
            } else if (result.isWarning()) {
                warning << tr("Import from %1 failed (%2)").arg(result.path, result.message);
            } else if (result.isInfo()) {
                success << tr("Import from %1 successful (%2)").arg(result.path, result.message);
            } else {
                success << tr("Imported from %1").arg(result.path);
            }
            notifyAbout(success, warning, error);
        });
        m_inFileUpdate = true;
    }
}

ShareObserver::Result ShareObserver::importShare(const QString& path, QHash<QString, bool>* hostCache)
{
    if (!KeeShare::active().in) {
        return {};
    }
    const auto changePath = resolvePath(path, m_db);
    auto shareGroup = m_shareToGroup.value(changePath);
    if (!shareGroup) {
        qWarning("Group for %s does not exist", qPrintable(path));
        return {};
    }
    const auto reference = KeeShare::referenceOf(shareGroup);
    if (reference.type == KeeShareSettings::Inactive) {
        // changes of inactive references are ignored
        return {};
    }
    if (reference.type == KeeShareSettings::ExportTo) {
        // changes of export only references are ignored
        return {};
    }

    Q_ASSERT(shareGroup->database() == m_db);
    Q_ASSERT(shareGroup == m_db->rootGroup()->findGroupByUuid(shareGroup->uuid()));
    const auto resolvedPath = resolvePath(reference.path, m_db);
    QHash<QString, bool> localHostCache;
    QHash<QString, bool>& activeCache = hostCache ? *hostCache : localHostCache;
    if (!isSharePathReachable(resolvedPath, reference.uncTimeout, activeCache)) {
        qDebug("KeeShare: Network share host not reachable within %d seconds, skipping import", reference.uncTimeout);
        return {};
    }
    return ShareImport::containerInto(resolvedPath, reference, shareGroup);
}

QSharedPointer<Database> ShareObserver::database()
{
    return m_db;
}

QList<ShareObserver::Result> ShareObserver::exportShares(bool* skippedUnreachable)
{
    QList<Result> results;
    struct Reference
    {
        KeeShareSettings::Reference config;
        const Group* group;
        QString resolvedPath;
    };

    QMap<QString, QList<Reference>> references;
    const auto groups = m_db->rootGroup()->groupsRecursive(true);
    for (const auto* group : groups) {
        const auto reference = KeeShare::referenceOf(group);
        if (!reference.isExporting()) {
            continue;
        }
        references[reference.path] << Reference{reference, group, resolvePath(reference.path, m_db)};
    }

    for (auto it = references.cbegin(); it != references.cend(); ++it) {
        if (it.value().count() != 1) {
            const auto path = it.value().first().config.path;
            QStringList groupnames;
            for (const auto& reference : it.value()) {
                groupnames << reference.group->name();
            }
            results << Result{
                path, Result::Error, tr("Conflicting export target path %1 in %2").arg(path, groupnames.join(", "))};
        }
    }
    if (!results.isEmpty()) {
        // We need to block export due to config
        return results;
    }

    QHash<QString, int> maxHostTimeout;
    for (auto it = references.cbegin(); it != references.cend(); ++it) {
        const auto& ref = it.value().first();
        const QString host = KeeShareSettings::Reference::extractUncHost(ref.resolvedPath).toLower();
        if (!host.isEmpty()) {
            maxHostTimeout[host] = qMax(maxHostTimeout.value(host, 0), ref.config.uncTimeout);
        }
    }

    QHash<QString, bool> hostCache;
    for (auto it = references.cbegin(); it != references.cend(); ++it) {
        auto reference = it.value().first();
        const QString& resolvedPath = reference.resolvedPath;
        const bool isUnc = KeeShareSettings::Reference::isUncPath(resolvedPath);
        if (isUnc) {
            const QString host = KeeShareSettings::Reference::extractUncHost(resolvedPath).toLower();
            const int probeTimeout = maxHostTimeout.value(host, reference.config.uncTimeout);
            if (!isSharePathReachable(resolvedPath, probeTimeout, hostCache)) {
                qDebug("KeeShare: Network share host not reachable within %d seconds, skipping export", probeTimeout);
                if (skippedUnreachable) {
                    *skippedUnreachable = true;
                }
                continue;
            }
            if (m_skippedShares.contains(resolvedPath) && reference.config.isImporting()) {
                results << Result{reference.config.path,
                                  Result::Warning,
                                  tr("Share was unreachable on open; reopen database to synchronize before exporting")};
                continue;
            }
        }
        auto watcher = m_fileWatchers.value(resolvedPath);
        if (watcher) {
            watcher->stop();
        }

        // TODO: save new path into group settings if not saving to signed container anymore
        results << ShareExport::intoContainer(resolvedPath, reference.config, reference.group);

        if (watcher) {
            watcher->start(resolvedPath, FileWatchPeriod, FileWatchSize);
        }
    }
    return results;
}

void ShareObserver::handleDatabaseSaved()
{
    if (!KeeShare::active().out) {
        return;
    }
    QStringList error;
    QStringList warning;
    QStringList success;
    bool skippedUnreachable = false;

    const auto results = exportShares(&skippedUnreachable);
    if (skippedUnreachable) {
        warning << tr("Network share host unreachable, sync skipped");
    }
    for (const Result& result : results) {
        if (!result.isValid()) {
            Q_ASSERT(result.isValid());
            continue;
        }
        if (result.isError()) {
            error << tr("Export to %1 failed (%2)").arg(result.path).arg(result.message);
        } else if (result.isWarning()) {
            warning << tr("Export to %1 failed (%2)").arg(result.path).arg(result.message);
        } else if (result.isInfo()) {
            success << tr("Export to %1 successful (%2)").arg(result.path).arg(result.message);
        } else {
            success << tr("Export to %1").arg(result.path);
        }
    }
    notifyAbout(success, warning, error);
}

ShareObserver::Result::Result(const QString& path, ShareObserver::Result::Type type, const QString& message)
    : path(path)
    , type(type)
    , message(message)
{
}

bool ShareObserver::Result::isValid() const
{
    return !path.isEmpty() || !message.isEmpty();
}

bool ShareObserver::Result::isError() const
{
    return !message.isEmpty() && type == Error;
}

bool ShareObserver::Result::isInfo() const
{
    return !message.isEmpty() && type == Info;
}

bool ShareObserver::Result::isWarning() const
{
    return !message.isEmpty() && type == Warning;
}
