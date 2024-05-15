package web

import (
	"bytes"
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"github.com/wetor/PPPwn_go/internal/logger"
	"go.uber.org/zap"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

type WebSocket struct {
	upgrader   *websocket.Upgrader
	wsConnLock sync.Mutex
	wsConns    []*websocket.Conn
	logList    *list.List

	log *zap.SugaredLogger

	notify       chan []byte
	logNotifyCap int // 暂停监听状态最多储存的日志数量
}

type WebSocketOption struct {
	LogNotifyCap int
	Notify       chan []byte
}

func NewWebSocket(opts *WebSocketOption) *WebSocket {
	return &WebSocket{
		upgrader: &websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		logList:      list.New(),
		log:          logger.GetLogger().Named("websocket"),
		notify:       opts.Notify,
		logNotifyCap: opts.LogNotifyCap,
	}
}

func (w *WebSocket) Run(ctx context.Context) {
	for {
		exit := false
		func() {
			if err := recover(); err != nil {
				w.log.Error(err)
			}
			select {
			case <-ctx.Done():
				exit = true
				return
			case logData := <-w.notify:
				if logger.GetLogNotify() == logger.NotifyEnabled {
					data := bytes.NewBuffer(nil)
					if w.logList.Len() > 0 {
						data.WriteString(fmt.Sprintf(`{"type":"log","count":%d}`, w.logList.Len()))
						for e := w.logList.Front(); e != nil; e = e.Next() {
							data.WriteString("\n\n")
							data.WriteString(e.Value.(string))
						}
						w.logList.Init()
					} else {
						data.WriteString(`{"type":"log","count":1}`)
					}
					data.WriteString("\n\n")
					data.Write(logData)

					w.wsConnLock.Lock()
					for _, conn := range w.wsConns {
						if err := conn.WriteMessage(websocket.TextMessage, data.Bytes()); err != nil {
							w.log.Error(err)
						}
					}
					w.wsConnLock.Unlock()
				} else if w.logNotifyCap > 0 && logger.GetLogNotify() == logger.NotifyPaused {
					w.logList.PushBack(string(logData))
					if w.logList.Len() > w.logNotifyCap {
						w.logList.Remove(w.logList.Front())
					}
				}
			}
		}()
		if exit {
			return
		}
	}
}

func (w *WebSocket) addConn(conn *websocket.Conn) {
	w.wsConnLock.Lock()
	w.wsConns = append(w.wsConns, conn)
	w.wsConnLock.Unlock()
}

func (w *WebSocket) deleteConn(conn *websocket.Conn) {
	w.wsConnLock.Lock()
	for i, c := range w.wsConns {
		if c == conn {
			w.wsConns = append(w.wsConns[:i], w.wsConns[i+1:]...)
			break
		}
	}
	w.wsConnLock.Unlock()
}

func (w *WebSocket) wsHandler(resp http.ResponseWriter, req *http.Request, before func(), after func()) {
	conn, err := w.upgrader.Upgrade(resp, req, nil)
	if err != nil {
		logger.Error(err)
		return
	}
	if before != nil {
		before()
	}

	w.addConn(conn)
	defer func() {
		w.deleteConn(conn)
		_ = conn.Close()
		if after != nil {
			after()
		}
	}()
	cmd := &Command{}
	cmd.Init()
	exit := false
	cmd.SetActionFunc(CommandLogTerminate, func() error {
		exit = true
		return nil
	})
	for {
		messageType, data, err := conn.ReadMessage()
		if messageType == websocket.CloseMessage {
			break
		}
		if err != nil {
			w.log.Errorf("read message failed. err: %v", err)
			break
		}
		err = json.Unmarshal(data, cmd)
		if err != nil {
			w.log.Errorf("unmarshal command failed. err: %v", err)
		}
		err = cmd.Execute()
		if err != nil {
			w.log.Errorf("execute command failed. err: %v", err)
		} else {
			w.log.Infof("execute command success. result: %v", string(data))
		}
		if exit {
			break
		}
	}
}
