import { createRequire } from 'node:module';
const runtimeRequire = createRequire(import.meta.url);
function loadNodeSqlite() {
    try {
        return runtimeRequire('node:sqlite');
    }
    catch (cause) {
        throw new Error('Android/Termux requires Node.js 22.13 or newer for the built-in node:sqlite database driver.', { cause });
    }
}
function numberResult(value) {
    const n = Number(value);
    if (!Number.isSafeInteger(n)) {
        throw new Error(`SQLite returned an integer outside JavaScript's safe range: ${value}`);
    }
    return n;
}
function wrapStatement(statement) {
    return {
        get: (...params) => statement.get(...params),
        all: (...params) => statement.all(...params),
        run: (...params) => {
            const result = statement.run(...params);
            return {
                changes: numberResult(result.changes),
                lastInsertRowid: numberResult(result.lastInsertRowid),
            };
        },
    };
}
/**
 * `node:sqlite` adapter used on Android, where better-sqlite3 does not publish
 * prebuilt binaries. It exposes only the small synchronous database contract
 * the server uses and implements better-sqlite3-style nested transactions with
 * savepoints.
 */
export const nodeSqliteFactory = (resolvedPath) => {
    const { DatabaseSync } = loadNodeSqlite();
    const raw = new DatabaseSync(resolvedPath);
    let transactionDepth = 0;
    let savepointSequence = 0;
    const database = {
        name: resolvedPath,
        memory: resolvedPath === ':memory:',
        prepare: (sql) => wrapStatement(raw.prepare(sql)),
        exec: (sql) => raw.exec(sql),
        pragma: (source) => raw.prepare(`PRAGMA ${source}`).all(),
        close: () => raw.close(),
        transaction: (fn) => {
            const wrapped = function (...args) {
                const outermost = transactionDepth === 0;
                const savepoint = `freellmapi_tx_${++savepointSequence}`;
                raw.exec(outermost ? 'BEGIN' : `SAVEPOINT ${savepoint}`);
                transactionDepth += 1;
                try {
                    const result = fn.apply(this, args);
                    if (result && typeof result.then === 'function') {
                        throw new Error('SQLite transaction callbacks must be synchronous');
                    }
                    raw.exec(outermost ? 'COMMIT' : `RELEASE SAVEPOINT ${savepoint}`);
                    return result;
                }
                catch (error) {
                    try {
                        if (outermost) {
                            raw.exec('ROLLBACK');
                        }
                        else {
                            raw.exec(`ROLLBACK TO SAVEPOINT ${savepoint}`);
                            raw.exec(`RELEASE SAVEPOINT ${savepoint}`);
                        }
                    }
                    catch {
                        // Preserve the original callback/commit error.
                    }
                    throw error;
                }
                finally {
                    transactionDepth -= 1;
                }
            };
            return wrapped;
        },
    };
    return database;
};
//# sourceMappingURL=node-sqlite.js.map