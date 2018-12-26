package mongo

import (
	"errors"
	"fmt"
	"time"

	"github.com/globalsign/mgo"
)

type MongoFactory struct {
	session *mgo.Session
}

func NewMongoFactory(dsn string, maxOpenConn int, connectTimeout time.Duration) (factory *MongoFactory, err error) {

	session, err := mgo.DialWithTimeout(dsn, connectTimeout)
	if err != nil {
		return
	}

	session.SetMode(mgo.PrimaryPreferred, true)
	session.SetPoolLimit(maxOpenConn)
	session.SetSyncTimeout(3000 * time.Millisecond)

	factory = &MongoFactory{session: session}

	return
}

func (factory *MongoFactory) CreateIndex(dbName, collName string, index mgo.Index) error {
	session, err := factory.Get()
	if err != nil {
		return err
	}
	defer factory.Put(session)

	coll := session.DB(dbName).C(collName)
	coll.EnsureIndex(index)

	return nil
}

func (factory *MongoFactory) Get() (session *mgo.Session, err error) {

	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprintf("%v", r))
		}
	}()

	if err = factory.session.Ping(); err != nil {
		factory.session.Refresh()
		err = factory.session.Ping()
		if err != nil {
			return
		}
	}

	session = factory.session.Copy()

	return
}

func (factory *MongoFactory) Put(session *mgo.Session) {
	if session != nil {
		session.Close()
	}
}

func (factory *MongoFactory) Close() {
	if factory.session != nil {
		factory.session.Close()
	}
}
